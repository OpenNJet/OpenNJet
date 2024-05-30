/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2024  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_core.h>
#include <njt_config.h>
#include <njt_event.h>

#include <jansson.h>
#include <njet_iot_emb.h>
#include "openrsync/extern.h"
#include <njt_gossip_module.h>
#include <njt_stream.h>

extern njt_module_t  njt_gossip_module;
extern sig_atomic_t  njt_reconfigure;

#define NJT_KEEP_MASTER_CYCLE   1

#define NJT_HELPER_CMD_NO       0
#define NJT_HELPER_CMD_STOP     1
#define NJT_HELPER_CMD_RESTART  2

#define NJT_HELPER_VER          1

#define NJT_HELPER_RSYNC_NODEINFO_TOPIC "/gossip/nodeinfo"
#define NJT_HELPER_RSYNC_FILE_TOPIC     "/dyn/fileupload"


typedef unsigned int (*helper_check_cmd_fp)(void *ctx);


typedef struct {
    njt_str_t   conf_fn;
    njt_str_t   conf_fullfn;
    helper_check_cmd_fp check_cmd_fp;
    void *ctx;
    void *cycle;
} helper_param;

static struct evt_ctx_t *rsync_mqtt_ctx;

struct rsync_status {
    int               is_master;
    int               master_index;
    int               port;
    int               daemon_start;
    int               full_sync_finished;
    char              master_url[1024]; // 1k is enough
} *rsync_status;

struct rsync_param {
    // char      *sync_dir;  hardcoded to './data/'
    njt_int_t  client_max_retry;
    char      *mqtt_conf_fn; // mqtt cong file, for subscribe
    char      *mqtt_client_id; 
} rsync_param;


static void njt_helper_rsync_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx);
static void njt_helper_rsync_loop_mqtt(njt_event_t *ev);

njt_shm_t *njt_helper_rsync_shm;
njt_slab_pool_t *njt_helper_rsync_shpool;

/* shared rsync status between processes */
njt_int_t
njt_helper_rsync_shm_init(njt_cycle_t *cycle) {
    njt_shm_t *shm;
    shm = njt_palloc(cycle->pool, sizeof(njt_shm_t));
    if (shm == NULL) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "failed alloc rsync shm");
        exit(2);
    }
    njt_str_set(&shm->name ,"njt_helper_rsync_shm");
    shm->size = 8 * 1024; // 4k is enough
    shm->log = cycle->log;

    if (njt_shm_alloc(shm) != NJT_OK) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "failed alloc rsync shm");
        exit(2);
    }

    njt_helper_rsync_shm = shm;

    njt_slab_pool_t  *sp;
    sp = (njt_slab_pool_t *) shm->addr;
    sp->end = shm->addr + shm->size;
    sp->min_shift = 3;
    sp->addr = shm->addr;
    sp->next = NULL; // for dyn_slab
    sp->first = sp; // for dyn_slab

    if (njt_shmtx_create(&sp->mutex, &sp->lock, NULL) != NJT_OK) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "failed alloc rsync shmtx");
        exit(2);
    }

    njt_slab_init(sp);

    njt_helper_rsync_shpool = sp;

    rsync_status = njt_slab_alloc(sp, sizeof(struct rsync_status));
    if (rsync_status == NULL) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "failed alloc rsync status");
        exit(2);
    }
    njt_memzero(rsync_status, sizeof(struct rsync_status));
    rsync_status->is_master = 1; // doesn't know master yet, set self as master

    return NJT_OK;
}

char *
njt_helper_rsync_get_host_addr(){
    char *ret;

    njt_shmtx_lock(&njt_helper_rsync_shpool->mutex);
    ret = strdup(rsync_status->master_url);
    njt_shmtx_unlock(&njt_helper_rsync_shpool->mutex);

    if (strlen(ret) == 0) {
        return NULL;
    }

    return ret;
}


static void
njt_helper_rsync_iot_set_timer(njt_event_handler_pt h, int interval, struct evt_ctx_t *ctx)
{
    njt_event_t *ev;
    njt_connection_t *c = njt_palloc(njt_cycle->pool, sizeof(njt_connection_t));
    njt_memzero(c, sizeof(njt_connection_t));

    ev = njt_palloc(njt_cycle->pool, sizeof(njt_event_t));
    njt_memzero(ev, sizeof(njt_event_t));
    ev->log = njt_cycle->log;
    ev->handler = h;
    ev->cancelable = 1;
    ev->data = c;
    c->fd = (njt_socket_t)-1;
    c->data = ctx;
    njt_add_timer(ev, interval);
}


static void
njt_helper_rsync_iot_conn_timeout(njt_event_t *ev)
{
    njt_connection_t *c = (njt_connection_t *)ev->data;
    struct evt_ctx_t *ctx = (struct evt_ctx_t *)c->data;
    int ret;
    if (ev->timedout) {
        ret = njet_iot_client_connect(3, 5, ctx);
        if (ret != 0) {
            if (ret == -5) {
                //client is connecting or has connected
                return;
            }
            njt_add_timer(ev, 1000);
        } else {
            //connect ok, register io
            njt_helper_rsync_iot_register_outside_reader(njt_helper_rsync_loop_mqtt, ctx);
        }
    }
}


static void
njt_helper_rsync_loop_mqtt(njt_event_t *ev)
{
    int ret;
    njt_connection_t *c = (njt_connection_t *)ev->data;
    struct evt_ctx_t *ctx = (struct evt_ctx_t *)c->data;
    if (ev->timer_set) {
        njt_del_timer(ev);
    }
    ret = njet_iot_client_run(ctx);
    switch (ret) {
    case 0:
        njt_add_timer(ev, 50);
        return;
    case 4:  // no connection
    case 19: // lost keepalive
    case 7:  // lost connection
        njt_helper_rsync_iot_set_timer(njt_helper_rsync_iot_conn_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
        break;
    default:
        njt_log_error(NJT_LOG_ERR, ev->log, 0, "mqtt client run:%d, what todo ?", ret);
        njt_helper_rsync_iot_set_timer(njt_helper_rsync_iot_conn_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
    }
    return;
}


static void
njt_helper_rsync_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx)
{
    int fd;
    njt_event_t *rev, *wev;
    fd = njet_iot_client_socket(ctx);
    njt_connection_t *c = njt_palloc(njt_cycle->pool, sizeof(njt_connection_t));
    njt_memzero(c, sizeof(njt_connection_t));

    rev = njt_palloc(njt_cycle->pool, sizeof(njt_event_t));
    njt_memzero(rev, sizeof(njt_event_t)); wev = njt_palloc(njt_cycle->pool, sizeof(njt_event_t)); njt_memzero(wev, sizeof(njt_event_t)); rev->log = njt_cycle->log;
    rev->handler = h;
    rev->data = c;
    rev->cancelable = 1;
    wev->data = c;
    wev->log = njt_cycle->log;
    wev->ready = 1;

    c->fd = (njt_socket_t)fd;
    // c->data=cycle;
    c->data = ctx;

    c->read = rev;
    c->write = wev;

    njt_log_error(NJT_LOG_NOTICE, rev->log, 0, "kv module connect ok, register socket:%d", fd);
    if (njt_add_event(rev, NJT_READ_EVENT, 0) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, rev->log, 0, "add io event for mqtt failed");
        return;
    }
    njt_add_timer(rev, 1000); // tips: trigger every 1s at least, to process misc things like ping/pong
}


void
njt_helper_rsync_client_start(njt_array_t *files, int retry)
{ 
    size_t       argc, i, host_len; 
    char       **argv, *host_addr;
    njt_str_t   *args;
    njt_pid_t    pid;


    pid = fork();

    if (pid < 0) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "fork failed in njt_helper_rsync start");
        return;
    }

    if (pid > 0) {
        return; // parent
    }

    for (i = 0; i <= (size_t)retry; i++) {

        if (files == NULL) {
            // ./openrsync -t -r remote_ip:port/data/ ./data
            argc = 6;
            if ((argv = calloc(argc, sizeof(char *))) == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "calloc failed in njt_helper_rsync start");
                return;
            }
            argv[0] = "./openrsync"; // nouse now
            argv[1] = "-t";
            argv[2] = "-v";
            argv[3] = "-v";
            argv[4] = njt_helper_rsync_get_host_addr();
            if (argv[3] == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "no master ip specified");
                return;
            }
            argv[5] = "./data/";

        } else {
            // gentrate argc argv for sync specify files
            argc = files->nelts + 4;
            if ((argv = calloc(argc, sizeof(char *))) == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "calloc failed in njt_helper_rsync start");
                return;
            }

            argv[0] = "./openrsync"; // nouse now
            argv[1] = "-t";
            argv[2] = "-v";
                // host_addr :    ip:port/data/
            host_addr = njt_helper_rsync_get_host_addr();
            if (host_addr == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "master_ip and port is null, return");
                return;
            } 
            host_len = strlen(host_addr);
            args = files->elts;
            argv[3] = malloc(host_len + args[0].len);
            memcpy(argv[3], host_addr, (size_t)host_len);
            memcpy(argv[3]+host_len, args[0].data, args[0].len);
            // now we only support one file
            // for (j = 1 ; j < files->nelts; j++) {
            //     argv[3+j] = ":" (char *)args[j].data;
            // }
            argv[argc - 1] = "./data";
        }

        // printf ("argc %ld, argv: ", argc);
        // for (k = 0; k < argc; k++) {
        //     printf (" %s", argv[k]);
        // }
        // printf("\n");

        // 0 success, 1 failed
        int rc = njt_start_rsync(argc, argv);
        printf("i: %ld, rc: %d\n", i, rc);
        if ( rc == 0) {
            break; // rsync success
        }
        njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "njt_helper_rsync client retry %d times", i);
        sleep((i+1 > 10) ? 10 : i+1);
        if (rc == 2) { // rc = 2  rsync_connection failed, will try endlessly, rc == 1, receiver failed, try at most maxretry times
            i--;
        }
    }
    exit(0);
}


void
njt_helper_rsync_master_change_handler(const char *cmsg, int msg_len)
{
    char      *cp, *msg, *mip, *lip, *port;
    int        p;
    njt_str_t  new_host;

    // master_ip:192.168.40.117,local_ip:192.168.40.117,sync_port:0,ctrl_port:28081
    msg = strdup(cmsg);
    if ((cp = strchr(msg, ',')) == NULL) { 
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "parsing master ip failed, msg '%s'", msg);
        return;
    }
    *cp++ = 0;
    if (strncmp(msg, "master_ip:", 10) != 0) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "parsing master ip failed, msg '%s'", msg);
        return;
    }
    mip = msg+10;

    msg = cp;
    if ((cp = strchr(msg, ',')) == NULL) { 
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "parsing local ip failed, msg '%s'", msg);
        return;
    }
    *cp++ = 0;
    if (strncmp(msg, "local_ip:", 9) != 0) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "parsing local ip failed, msg '%s'", msg);
        return;
    }
    lip = msg+9;

    msg = cp;
    if ((cp = strchr(msg, ',')) == NULL) { 
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "parsing sync port failed, msg '%s'", msg);
        return;
    }
    *cp++ = 0;
    if (strncmp(msg, "sync_port:", 10) != 0) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "parsing sync port failed, msg '%s'", msg);
        return;
    }
    port = msg+10;

    if ((p = njt_atoi((u_char *)port, strlen(port))) == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "parsing sync port failed, msg '%s'", msg);
        return;
    } 

    if (p <= 0 || p >= 65536) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "parsing sync port failed, msg '%s'", msg);
        return;
    }

    if (strcmp(mip, lip) == 0) {
        rsync_status->is_master = 1;
    } else {
        rsync_status->is_master = 0;
    }

    rsync_status->port = p;

    if (rsync_status->is_master) {
        return; // master do nothing
    }

    // hard coded sync dir to '/data/'
    new_host.len = strlen(mip) + strlen(port) + strlen("/data/") + 1 + 1;
    new_host.data = njt_pcalloc(njt_cycle->pool, new_host.len);
    if (new_host.data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "parsing sync port failed, msg '%s'", msg);
        return;
    }
    njt_sprintf(new_host.data, "%s:%d/data/", mip, rsync_status->port);

    njt_shmtx_lock(&njt_helper_rsync_shpool->mutex);
    njt_memcpy(rsync_status->master_url, new_host.data, new_host.len);
    njt_shmtx_unlock(&njt_helper_rsync_shpool->mutex);
    njt_pfree(njt_cycle->pool, new_host.data);

    if (!rsync_status->full_sync_finished && !rsync_status->is_master) {
        sleep(1);
        njt_helper_rsync_client_start(NULL, rsync_param.client_max_retry);
        rsync_status->full_sync_finished = 1;
    } 

    return;
}


void njt_helper_rsync_file_change_handler(const char *msg, size_t msg_len)
{
    // {"filename":"d6d567b0ad5f124e6d592e1fdee3e2eb.dat"}
    njt_pool_t    *dyn_pool;
    njt_array_t   *files;
    size_t         n_files = 1, f_len;
    njt_str_t     *file;
    json_t *root, *filename;
    json_error_t   jerror;

    if (rsync_status->is_master) {
        return; // msster do nothing 
    }

    const char *fname;
    root = json_loads(msg, 0, &jerror);
    if (root == NULL)  {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "json root is null, msg: '%s'", msg);
        return;
    }
    filename = json_object_get(root, "filename");
    if (filename == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "filename is null, msg: '%s'", msg);
        return;
    }
    fname = json_string_value(filename);
    f_len = strlen(fname);
    printf("filename: %s\n", fname);


    dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (dyn_pool == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rsync helper failed to allocate dyn pool");
        return;
    }
    // parse msg to arrsy of file
    files = njt_array_create(dyn_pool, n_files, sizeof(njt_str_t));
    if (files == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rsync helper failed to create array");
        return;
    }

    file = njt_array_push(files);
    file->data = njt_pcalloc(dyn_pool, f_len + 1);
    njt_memcpy(file->data, fname, f_len);
    file->len = f_len + 1;
    
    // for more than one files, file_path is ':data/file'
    
    njt_helper_rsync_client_start(files, rsync_param.client_max_retry);
    njt_destroy_pool(dyn_pool);
}


njt_int_t njt_helper_rsync_daemon_stop(njt_pid_t pid) {
    int       signo; 
    njt_err_t err;

    // signo = njt_signal_value(NJT_TERMINATE_SIGNAL); SIGTERM cann't kill the process
    signo = SIGKILL;
    if (kill(pid, signo) == -1) {
        err = njt_errno;
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, err,
                "kill rsync daemon ctrl-o(%P, %d) failed", pid, signo);
        return NJT_ERROR;
    }

    return NJT_OK;
}


static int rsync_msg_callback(const char *topic, const char *msg, int msg_len, void *out_data)
{
    int node_topic_l = strlen(NJT_HELPER_RSYNC_NODEINFO_TOPIC);
    int file_topic_l = strlen(NJT_HELPER_RSYNC_FILE_TOPIC);
    int topic_l = strlen(topic);

    printf("msg: %s\n", msg);

    if (msg == NULL || msg_len == 0) {
        return NJT_OK;
    }

    if (njt_exiting || njt_terminate) {
        //when process is exiting or terminate, skip msg processing
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "process is existing, skip kv handling");
        return NJT_OK;
    }


    if (topic_l == node_topic_l && 0 == memcmp(topic, NJT_HELPER_RSYNC_NODEINFO_TOPIC, node_topic_l)) {
        njt_helper_rsync_master_change_handler(msg, msg_len);
    }

    if (topic_l == file_topic_l && 0 == memcmp(topic, NJT_HELPER_RSYNC_FILE_TOPIC, file_topic_l)) {
        njt_helper_rsync_file_change_handler(msg, msg_len);
    }

    return NJT_OK;
}



njt_pid_t
njt_helper_rsync_daemon_start(njt_cycle_t *cycle, char *bind_address, int port)
{

    int         argc, i;
    char      **argv;
    njt_pid_t   pid;
    const char *name = "njet rsync daemon process";




    pid = fork();
    if (pid == 0) {
        if (prctl(PR_SET_NAME, (unsigned long) name) < 0) {
            njt_log_error(NJT_LOG_CRIT, cycle->log, 0, "failed to prctl()");
        }
            // ./openrsync -t -r -vvvv --sender --server --exclude data/data.mdb --exclude data/lock.mdb --exclude data/mosquitto.db . ./data/  
        argc = 18;

        if ((argv = calloc(argc, sizeof(char *))) == NULL) {
            njt_log_error(NJT_LOG_ERR, cycle->log ,0,  "alloc error");
        }

        char p[6];
        njt_memzero(p, 6);
        sprintf(p, "%d", port);

        argv[0] = "./openrsync"; // no use now
        argv[1] = "-r";
        argv[2] = "-t";
        argv[3] = "-vvvv";
        argv[4] = "--server";
        argv[5] = "--sender";
        argv[6] = "--exclude";
        argv[7] = "data.mdb";
        argv[8] = "--exclude";
        argv[9] = "lock.mdb";
        argv[10] = "--exclude";
        argv[11] = "mosquitto.db";
        argv[12] = "--address";
        argv[13] = strdup(bind_address);
        argv[14] = "--port";
        argv[15] = p;
        argv[16] = ".";
        argv[17] = "./data/";

        printf ("argc 20, argv: ");
        for (i = 0; i < argc; i++) {
            printf (" %s", argv[i]);
        }
        printf("\n");
        njt_start_rsync(argc, argv);
    } else if (pid > 0) {
        return pid;
    } else {
        njt_log_error(NJT_LOG_CRIT, cycle->log, 0, "failed to fork rsync daemon process");
        return NJT_INVALID_PID;
    }
    
    return 0;
}



njt_int_t njt_helper_rsync_parse_json(njt_cycle_t *cycle, char *conf_fn) {
    // read json to str
    json_t *json;
    json_error_t error;
    json_t *cid, *mqtt_conf_fn, *max_retry; 
    struct rsync_param *param;

    param = &rsync_param;

    json = json_load_file(conf_fn, 0, &error);
    if (json == NULL) {
        return NJT_ERROR;
    }

    mqtt_conf_fn = json_object_get(json, "mqtt_conf_file");
    if (mqtt_conf_fn == NULL) {
        param->mqtt_conf_fn = "conf/iot.conf";
    } else {
        param->mqtt_conf_fn = strdup(json_string_value(mqtt_conf_fn));
    }

    // sync_dir = json_object_get(json, "sync_dir");
    // if (sync_dir == NULL) {
    //     param->sync_dir = "/data/";
    // } else {
    //     param->sync_dir = strdup(json_string_value(sync_dir));
    // }

    cid = json_object_get(json, "mqtt_client_id");
    if (cid == NULL) {
        param->mqtt_client_id = "rsync_mqtt_client";
    } else {
        param->mqtt_client_id = strdup(json_string_value(cid));
    }

    // port = json_object_get(json, "port");
    // if (port == NULL) {
    //     param->port = 8873;
    // } else {
    //     param->port = (njt_int_t)json_integer_value(port);
    //     if (param->port == 0) {
    //         param->port = 8873;
    //     }
    // }

    max_retry = json_object_get(json, "max_retry");
    if (max_retry == NULL) {
        param->client_max_retry = 3;
    } else {
        param->client_max_retry = (njt_int_t)json_integer_value(max_retry);
        if (param->client_max_retry == 0) {
            param->client_max_retry = 3;
        }
    }

    njt_log_debug(NJT_LOG_DEBUG, cycle->log, 0, "parse rsync conf file successfully");


    return NJT_OK;
}


static njt_int_t njt_helper_rsync_init_mqtt_process (njt_cycle_t *cycle)
{
    char *prefix;
    int ret;

    char *localcfg = rsync_param.mqtt_conf_fn;
    char *client_id = rsync_param.mqtt_client_id;
    char log[1024] = "logs/rsync.log";

    njt_cycle = cycle;

    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    njt_memcpy(prefix, cycle->prefix.data, cycle->prefix.len);
    
    prefix[cycle->prefix.len] = '\0';

    rsync_mqtt_ctx = njet_iot_client_init(prefix, localcfg, NULL, rsync_msg_callback, client_id, log, cycle);
    njt_free(prefix);
    

    // TODO FIXME
    njet_iot_client_add_topic(rsync_mqtt_ctx, "/ins/loc/#");
    njet_iot_client_add_topic(rsync_mqtt_ctx, NJT_HELPER_RSYNC_NODEINFO_TOPIC "/#");
    njet_iot_client_add_topic(rsync_mqtt_ctx, NJT_HELPER_RSYNC_FILE_TOPIC "/#");

    if (rsync_mqtt_ctx == NULL) {
        njet_iot_client_exit(rsync_mqtt_ctx);
        return NJT_ERROR;
    };

    ret = njet_iot_client_connect(3, 5, rsync_mqtt_ctx);
    if (ret != 0) {
        njt_helper_rsync_iot_set_timer(njt_helper_rsync_iot_conn_timeout, 2000, rsync_mqtt_ctx);
    } else {
        njt_helper_rsync_iot_register_outside_reader(njt_helper_rsync_loop_mqtt, rsync_mqtt_ctx);
    };

    return NJT_OK;
}



njt_pid_t
njt_helper_rsync_start_process(njt_cycle_t *cycle, char *prefix, char *conf_fn) 
{
    njt_pid_t   rsync_pid;
    char        bind_address[16];
    
    njt_stream_conf_ctx_t 		*conf_ctx =NULL ;
	njt_gossip_srv_conf_t		*gscf =NULL;

    // first check gossip conf, get local ip and sync port
	conf_ctx =(njt_stream_conf_ctx_t *)cycle->conf_ctx[njt_stream_module.index];
	if (conf_ctx) 
		gscf = conf_ctx->srv_conf[njt_gossip_module.ctx_index];
	else {
		return NJT_INVALID_PID;
	}
    
    if (gscf == NULL) {
		return NJT_INVALID_PID;
    }

    if (gscf->node_info.sync_port == 0) {
        return  NJT_INVALID_PID;
    }

    njt_helper_rsync_shm_init(cycle);

    // if (njt_helper_rsync_parse_json(cycle, conf_fn) != NJT_OK) {
    //     njt_log_error(NJT_LOG_ERR, cycle->log, 0, "error in parsing rsync conf %s", conf_fn);
    //     return NJT_INVALID_PID;
    // }

    rsync_param.mqtt_conf_fn = conf_fn;
    rsync_param.client_max_retry = 16;
    rsync_param.mqtt_client_id = "rsync_mqtt_client";

    njt_memzero(bind_address, 16);
    sprintf(bind_address, "%d.%d.%d.%d", gscf->node_info.ip[0],
        gscf->node_info.ip[1], gscf->node_info.ip[2], gscf->node_info.ip[3]);
    printf("bind_addrss: %s, port: %d \n", bind_address, gscf->node_info.sync_port),
    rsync_pid = njt_helper_rsync_daemon_start(cycle, bind_address, gscf->node_info.sync_port);
    
    
    if (rsync_pid == NJT_INVALID_PID) {
        return NJT_INVALID_PID;
    }

    njt_helper_rsync_init_mqtt_process(cycle);

    return rsync_pid;
}


void 
njt_helper_run(helper_param param)
{
    njt_cycle_t     *cycle;
    unsigned int     cmd;
    njt_pid_t        rsync_daemon_pid;
    const char      *name = "njet rsync copilot";

    // now cwd is the directory specified by -p option
    cycle = param.cycle;
    njt_cycle = cycle; 
    njt_reconfigure = 1;

    rsync_daemon_pid = NJT_INVALID_PID; 

    for (;;) {
        if (njt_reconfigure) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper rsync start/reconfiguring");
            if (rsync_daemon_pid != NJT_INVALID_PID) {
                njt_helper_rsync_daemon_stop(rsync_daemon_pid);
            }
            // set process name
            if (prctl(PR_SET_NAME, (unsigned long) name) < 0) {
                njt_log_error(NJT_LOG_CRIT, cycle->log, 0, "failed to prctl()");
            }

            rsync_daemon_pid = njt_helper_rsync_start_process(cycle, (char *)cycle->prefix.data, (char *)param.conf_fn.data);
            printf("rsync_daemon_pid %d \n", rsync_daemon_pid);
            if (rsync_daemon_pid == NJT_INVALID_PID) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper rsync start/reconfiguring failed, unable to start rsync daemon, possible reasons (no gossip conf or port confliction)");
                exit(2);
            } else {
                njt_reconfigure = 0;
            }
            // njt_reconfigure = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper rsync start/reconfiguring done");
            sleep(1);
        }

        cmd = param.check_cmd_fp(cycle);
        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, -1);
        }

        if (cmd == NJT_HELPER_CMD_STOP) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper rsync exit");
            if (rsync_daemon_pid != NJT_INVALID_PID) {
                njt_helper_rsync_daemon_stop(rsync_daemon_pid);
            }
            break;            
        }

        if (cmd == NJT_HELPER_CMD_RESTART) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper rsync restart");
            njt_reconfigure = 1;
        }
    }
    
    return;
}


unsigned int njt_helper_check_version(void)
{
    return NJT_HELPER_VER;
}


/*
返回 1，表示该so的copilot进程，不会在reload的时候重启。
放回 0，表示该so的copilot进程，会在reload的时候重启。
注1：so可以不实现该接口。若不实现，则等同于返回0。
注2：如果so实现该接口并且返回1，那么在reload的时候该so的copilot进程不会重启，
但是有一点需要注意：reload的时候配置文件中需保留原helper指令，这是配置上的强制要求，
不满足此要求会导致reload失败。
*/
unsigned int njt_helper_ignore_reload(void)
{
    return 1; // don't reload
}


njt_module_t njt_helper_rsync_module = {0};
