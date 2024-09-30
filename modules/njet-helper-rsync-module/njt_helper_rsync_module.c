/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2024  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_core.h>
#include <njt_config.h>

#include <jansson.h>
#include <njt_event.h>
#include <njt_stream.h>
#include <njet_iot_emb.h>
#include <njt_gossip_module.h>
#include "njt_http_kv_module.h"
#include "openrsync/extern.h"
#include <utime.h>

extern njt_module_t  njt_gossip_module;
extern sig_atomic_t  njt_reconfigure;

#define NJT_KEEP_MASTER_CYCLE   1

#define NJT_HELPER_CMD_NO       0
#define NJT_HELPER_CMD_STOP     1
#define NJT_HELPER_CMD_RESTART  2

#define NJT_HELPER_VER          1

#define INOTIFY_WATCH_BUF_SIZE 4096

#define NJT_HELPER_RSYNC_FILE_TOPIC     "/dyn/filesync"
#define NJT_HELPER_RSYNC_NODEINFO_TOPIC "/gossip/nodeinfo"
#define NJT_HELPER_RSYNC_TIMER_CLIENT_RETRY 1

typedef unsigned int (*helper_check_cmd_fp)(void *ctx);


typedef struct {
    njt_str_t   conf_fn;
    njt_str_t   conf_fullfn;
    helper_check_cmd_fp check_cmd_fp;
    void *ctx;
    void *cycle;
    struct evt_ctx_t *mdb_ctx;
} helper_param;

struct rsync_status {
    int               is_master;
    int               master_index;
    int               port;
    int               daemon_start;
    int               full_sync_busy;
    int               watch_client_busy;
    int               master_changed;
    char              master_url[1024]; // 1k is enough
} *rsync_status;


typedef struct rsync_inotify_file_t{
    njt_str_t   watch_file;
    njt_int_t   watch_fd;
}rsync_inotify_file;


struct rsync_param {
    njt_int_t     refresh_interval;
    njt_int_t     client_max_retry;
    njt_array_t  *watch_files;
    njt_array_t  *ignore_files;
    char         *log_file;

    njt_flag_t    inotify_start;
    njt_int_t     inotify_fd;
    njt_connection_t c;
    njt_event_t   watch_rev;
    njt_event_t   watch_wev;

    helper_param *param;
} rsync_param;


static void njt_helper_rsync_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx);
static void njt_helper_rsync_loop_mqtt(njt_event_t *ev);

void njt_helper_rsync_syn_file(njt_str_t *syn_file);
void njt_helper_rsync_start_inotify();
void njt_helper_rsync_stop_inotify();

njt_shm_t               *njt_helper_rsync_shm;
njt_slab_pool_t         *njt_helper_rsync_shpool;
static njt_log_t        *sync_log;
static struct evt_ctx_t *rsync_mqtt_ctx;


void
njt_helper_rsync_init_log(njt_cycle_t *cycle)
{
    char  *prefix;

    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    memcpy(prefix, cycle->prefix.data, cycle->prefix.len);
    prefix[cycle->prefix.len] = '\0';

    njt_log_t *new_log = njt_log_init((u_char *)prefix, (u_char *)rsync_param.log_file);
    njt_free(prefix);

    if (new_log == NULL) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
                          "njt log init failed in rsync helper");
        exit(2);
    } 

    if (njt_set_stderr(new_log->file->fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
                          njt_set_stderr_n " failed");

    }
 
    sync_log = new_log;
}


/* shared rsync status between processes */
njt_int_t
njt_helper_rsync_shm_init(njt_cycle_t *cycle)
{
    njt_shm_t *shm;

    shm = njt_palloc(cycle->pool, sizeof(njt_shm_t));
    if (shm == NULL) {
        njt_log_error(NJT_LOG_EMERG, sync_log, 0, "failed alloc rsync shm");
        exit(2);
    }

    njt_str_set(&shm->name ,"njt_helper_rsync_shm");
    shm->size = 8 * 1024; // 4k is enough
    shm->log = cycle->log;
    if (njt_shm_alloc(shm) != NJT_OK) {
        njt_log_error(NJT_LOG_EMERG, sync_log, 0, "failed alloc rsync shm");
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
njt_helper_rsync_get_host_addr()
{
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

    njt_log_error(NJT_LOG_NOTICE, rev->log, 0, "rsync helper module connect ok, register socket:%d", fd);
    if (njt_add_event(rev, NJT_READ_EVENT, 0) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, rev->log, 0, "add io event for mqtt failed");
        return;
    }
    njt_add_timer(rev, 1000); // tips: trigger every 1s at least, to process misc things like ping/pong
}

// void
// njt_helper_rsync_client_start(njt_array_t *files, int retry)
// { 
//     size_t       argc, i, j, host_len; // k,
//     char       **argv, *host_addr;
//     njt_str_t   *args;
//     njt_pid_t    pid;

//     pid = fork();
//     if (pid < 0) {
//         njt_log_error(NJT_LOG_ERR, sync_log, 0, "fork failed in njt_helper_rsync start");
//         return;
//     }

//     if (pid > 0) {
//         return; // parent
//     }

//     for (i = 0; i <= (size_t)retry; i++) {
//         if (rsync_status->is_master) {
//             break;
//         }

//         if (files == NULL) {
//             // ./openrsync -t -r remote_ip:port/data/ ./data
//             argc = 6;
//             if ((argv = calloc(argc, sizeof(char *))) == NULL) {
//                 njt_log_error(NJT_LOG_ERR, sync_log, 0, "calloc failed in njt_helper_rsync start");
//                 return;
//             }
//             argv[0] = "./openrsync"; // nouse now
//             argv[1] = "-t";
//             argv[2] = "-v";
//             argv[3] = "-v";
//             argv[4] = njt_helper_rsync_get_host_addr_test();
//             if (argv[4] == NULL) {
//                 njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "no master ip specified");
//                 break;
//             }

//             // argv[4] = strdup("192.168.40.136:8873//root/bug/njet1.0/clb/");
//             argv[5] = "./data/";

//         } else {
//             // gentrate argc argv for sync specify files
//             argc = files->nelts + 4;
//             if ((argv = calloc(argc, sizeof(char *))) == NULL) {
//                 njt_log_error(NJT_LOG_ERR, sync_log, 0, "calloc failed in njt_helper_rsync start");
//                 break;
//             }

//             argv[0] = "./openrsync"; // nouse now
//             argv[1] = "-t";
//             if (retry == 1) {
//                 argv[2] = "-v"; // from timer handler, 
//             } else {
//                 argv[2] = "-vv"; // from msg handler
//             }
//             host_addr = njt_helper_rsync_get_host_addr(); // host_addr :    ip:port/data/
//             if (host_addr == NULL) {
//                 njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "master_ip and port is null, return");
//                 break;
//             } 
//             host_len = strlen(host_addr);
//             args = files->elts;
//             argv[3] = malloc(host_len + args[0].len + 1);
//             memcpy(argv[3], host_addr, (size_t)host_len);
//             memcpy(argv[3]+host_len, args[0].data, args[0].len);
//             argv[3][host_len + args[0].len] = 0;

//             for (j = 1 ; j < files->nelts; j++) {
//                 argv[3+j] = calloc(7+args[j].len+1, sizeof(char));
//                 memcpy(argv[3+j], ":data/", 6);
//                 memcpy(argv[3+j]+6, (char *)args[j].data, args[j].len);
//                 argv[3+j][args[j].len+6] = 0;
//             }
//             argv[argc - 1] = "./data";

//             if (argc == 5 && retry > 1) {
//                 njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "%s %s %s %s %s", argv[0], argv[1], argv[2], argv[3], argv[4]);
//             }
//         }

//         int rc = njt_start_rsync(argc, argv); // 0 success, 1 failed in client, 2 failed in connection

//         if ( rc == 0) {
//             break; // rsync success
//         }

//         njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "njt_helper_rsync client retry %d times", i);
//         sleep((i+1 > 10) ? 10 : i+1);
//         // if (rc == 2 && retry > 1) { // rc = 2  rsync_connection failed, will try endlessly, rc == 1, receiver failed, try at most maxretry times
//             // i--;
//         // }
//         if (files != NULL) {
//             // free argv generated from files
//             for (i = 0; i < files->nelts; i++){
//                 free(argv[3+i]);
//             }
//         }
//     }

//     if (retry == NJT_HELPER_RSYNC_TIMER_CLIENT_RETRY) {
//         rsync_status->watch_client_busy = 0;// only one process can reach here
//     }

//     if (files == NULL) {
//         rsync_status->full_sync_busy = 0; // only one process can reach here
//     }
//     exit(0);
// }



void
njt_helper_rsync_all_client_start()
{ 
    njt_pid_t               pid;
    njt_uint_t              i;
    rsync_inotify_file     *watch_files;

    pid = fork();
    if (pid < 0) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "fork failed in njt_helper_rsync start");
        return;
    }

    if (pid > 0) {
        return; // parent
    }

    if (rsync_status->is_master) {
        exit(0);
    }

    watch_files = rsync_param.watch_files->elts;

    for(i = 0; i < rsync_param.watch_files->nelts; i++){
        if (rsync_status->is_master){
            break;
        }
        njt_helper_rsync_syn_file(&watch_files[i].watch_file);
    }

    exit(0);
}



void
njt_helper_rsync_syn_file(njt_str_t *syn_file){
    size_t       argc, host_len; // k,
    char       **argv, *host_addr;
    u_char      *start, *last;

    if(syn_file == NULL || syn_file->len < 1){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "sync file should not be null");
        return;
    }


    if(syn_file->data[0] != '/'){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "sync file should must use absolute file:%V", syn_file);
        return;
    }

    // ./openrsync -t -r remote_ip:port/{file} {dst_dir}
    argc = 1 + 4;
    if ((argv = calloc(argc, sizeof(char *))) == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "calloc failed in njt_helper_rsync start");
        return;
    }

    argv[0] = "./openrsync"; // nouse now
    argv[1] = "-t";
    argv[2] = "-v"; // from timer handler, 
    // argv[2] = "-vv"; // from msg handler
    host_addr = njt_helper_rsync_get_host_addr(); // host_addr :    ip:port/data/
    if (host_addr == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "master_ip and port is null, return");
        goto sync_file_exit;
    } 
    host_len = strlen(host_addr);
    argv[3] = malloc(host_len + syn_file->len + 1);
    if(argv[3] == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rsyn malloc src file error when sync");
        goto sync_file_exit;
    }
    memcpy(argv[3], host_addr, (size_t)host_len);
    memcpy(argv[3] + host_len, syn_file->data, syn_file->len);
    argv[3][host_len + syn_file->len] = 0;

    //find last '/', as dir
    start = syn_file->data;
    last = syn_file->data + syn_file->len;
    while(last > start){
        if(*last != '/'){
            last--;
        }
    }

    argv[4] = malloc(last - start +2);
    if(argv[4] == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rsyn malloc dst dir error when sync");
        free(argv[3]);
        goto sync_file_exit;
    }

    memcpy(argv[4], start, last - start + 1);
    argv[4][last - start + 1] = 0;

    // argv[4] = strdup("192.168.40.136:8873//root/bug/njet1.0/clb/");
    njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "%s %s %s %s %s", argv[0], argv[1], argv[2], argv[3], argv[4]);

    int rc = njt_start_rsync(argc, argv); // 0 success, 1 failed in client, 2 failed in connection

    if ( rc != 0) {
        //todo: now just record log, and add to fail queue
        njt_log_error(NJT_LOG_ERR, sync_log, 0, 
            "rsyn error, param:%s %s %s %s %s", argv[0], argv[1], argv[2], argv[3], argv[4]);
    }

    free(argv[3]);
    free(argv[4]);

sync_file_exit:
    if(argv != NULL){
        free(argv);
    }
}

void
njt_helper_rsync_client_start(njt_str_t *syn_file)
{ 
    njt_pid_t    pid;

    pid = fork();
    if (pid < 0) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "fork failed in njt_helper_rsync start");
        return;
    }

    if (pid > 0) {
        return; // parent
    }

    if (rsync_status->is_master) {
        exit(0);
    }

    njt_helper_rsync_syn_file(syn_file);

    exit(0);
}


void
njt_helper_rsync_master_change_handler(const char *cmsg, int msg_len)
{
    char      *cp, *msg, *mip, *lip, *port;
    int        p;
    njt_str_t  new_host;

    // example msg  master_ip:192.168.40.117,local_ip:192.168.40.117,sync_port:0,ctrl_port:28081
    msg = (char *)(cmsg);
    if ((cp = strchr(msg, ',')) == NULL) { 
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing master ip failed, msg '%s'", msg);
        goto failed;
    }
    *cp++ = 0;
    if (strncmp(msg, "master_ip:", 10) != 0) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing master ip failed, msg '%s'", msg);
        goto failed;
    }
    mip = msg+10;

    msg = cp;
    if ((cp = strchr(msg, ',')) == NULL) { 
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing local ip failed, msg '%s'", msg);
        goto failed;
    }
    *cp++ = 0;
    if (strncmp(msg, "local_ip:", 9) != 0) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing local ip failed, msg '%s'", msg);
        goto failed;
    }
    lip = msg+9;

    msg = cp;
    if ((cp = strchr(msg, ',')) == NULL) { 
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing sync port failed, msg '%s'", msg);
        goto failed;
    }
    *cp++ = 0;
    if (strncmp(msg, "sync_port:", 10) != 0) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing sync port failed, msg '%s'", msg);
        goto failed;
    }
    port = msg+10;

    if ((p = njt_atoi((u_char *)port, strlen(port))) == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing sync port failed, msg '%s'", msg);
        goto failed;
    } 

    if (p <= 0 || p >= 65536) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing sync port failed, msg '%s'", msg);
        goto failed;
    }

    if (strcmp(mip, lip) == 0) {
        rsync_status->is_master = 1;
    } else {
        rsync_status->is_master = 0;
    }

    rsync_status->port = p;

    if (rsync_status->is_master) {
        njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "master node info: I AM MASTER");

        //need start inotify process
        if(!rsync_param.inotify_start){
            njt_helper_rsync_start_inotify();
        }else{
            //todo: maybe need check pid's process status
        }
        
        return;
    }

    // hard coded sync dir to '/data/'
    new_host.len = strlen(mip) + strlen(port) + 1;  //addtional ':'
    new_host.data = njt_pcalloc(njt_cycle->pool, new_host.len + 1);  //last used for '\0'
    if (new_host.data == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing sync port failed, msg '%s'", msg);
        return;
    }
    njt_sprintf(new_host.data, "%s:%d", mip, rsync_status->port);

    // njt_sprintf(new_host_test.data, "%s:%d//root/bug/njet1.0/clb/", mip, rsync_status->port);

    njt_shmtx_lock(&njt_helper_rsync_shpool->mutex);
    njt_memcpy(rsync_status->master_url, new_host.data, new_host.len);
    njt_shmtx_unlock(&njt_helper_rsync_shpool->mutex);
    njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "master node info: %s", rsync_status->master_url);
    njt_pfree(njt_cycle->pool, new_host.data);

    if (!rsync_status->is_master) {
        sleep(1); // leave enough time for master node rsync daemon to start

        //if self start inotify process, need kill inotify process
        if(rsync_param.inotify_start){
            njt_helper_rsync_stop_inotify();
        }

        //start sync all
        njt_helper_rsync_all_client_start(NULL);
    }

    return;

failed:
    return;
}


void
njt_helper_rsync_file_change_handler(const char *msg, size_t msg_len)
{
    njt_str_t      syn_file;
    json_t *root, *filename;
    json_error_t   jerror;

    if (rsync_status->is_master) {
        njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "I AM MASTER, DO nothing");
        return; // msster do nothing 
    }

    const char *fname;
    root = json_loads(msg, 0, &jerror);
    if (root == NULL)  {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "json root is null, msg: '%s'", msg);
        return;
    }

    filename = json_object_get(root, "filename");
    if (filename == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "filename is null, msg: '%s'", msg);
        return;
    }
    fname = json_string_value(filename);
    if (fname == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "fname is null, msg: '%s'", fname);
        return;
    }

    syn_file.data = (u_char *)fname;
    syn_file.len = strlen(fname);
    
    njt_log_error(NJT_LOG_INFO, sync_log, 0, "rsync helper syn filename:%V", &syn_file);
    njt_helper_rsync_client_start(&syn_file);
    json_decref(root);
}

njt_int_t
njt_helper_rsync_daemon_stop(njt_pid_t pid)
{
    int            signo; 
    njt_err_t      err;
    char*          path = "./data";
    struct dirent *entry;
    DIR           *dir;

    // signo = njt_signal_value(NJT_TERMINATE_SIGNAL); SIGTERM cann't kill the process
    signo = SIGKILL;
    if (kill(pid, signo) == -1) {
        err = njt_errno;
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, err,
                "kill rsync daemon ctrl-o(%P, %d) failed", pid, signo);
        return NJT_ERROR;
    }

    for ( ;; ) {
        if(waitpid(pid, NULL, WNOHANG) == 0) {
            njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
                    "kill rsync daemon ctrl-o(%P, %d) return 0, keep wait", pid, signo);
            usleep(10 * 1000);
        } else {
            break;
        }
    }

    // remove possible hidden files in ./data/
    dir = opendir(path);
    if (dir == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "./data directory is null");
        return NJT_ERROR;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            continue;
        }

        if (entry->d_name[0] == '.') {
            char filepath[300];
            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
            filepath[299] = 0;
            if (remove(filepath) == -1) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to rm hidden file %s", filepath);
                return NJT_ERROR;
            }
            njt_log_debug(NJT_LOG_DEBUG, njt_cycle->log, 0,  "Deleted: %s\n", filepath);
        }
    }

    if (closedir(dir) == -1) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to close dir %s", path);
        return NJT_ERROR;
    }

    return NJT_OK;
}


static int rsync_msg_callback(const char *topic, const char *msg, int msg_len, void *out_data)
{
    int node_topic_l = strlen(NJT_HELPER_RSYNC_NODEINFO_TOPIC);
    int file_topic_l = strlen(NJT_HELPER_RSYNC_FILE_TOPIC);
    int topic_l = strlen(topic);

    if (msg == NULL || msg_len == 0) {
        return NJT_OK;
    }
    njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "mqtt msg received '%s'", msg);

    if (njt_exiting || njt_terminate) {
        //when process is exiting or terminate, skip msg processing
        njt_log_error(NJT_LOG_INFO, sync_log, 0, "process is existing, skip kv handling");
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
    int         argc; // , i;
    char      **argv;
    njt_pid_t   pid;
    njt_uint_t  i, index;
    char       *name = "rsync server daemon";
    njt_str_t   *ignore_files;


    pid = fork();
    if (pid == 0) {
        njt_setproctitle(name);

        // ./openrsync -t -r -vvvv --sender --server --exclude data/data.mdb --exclude data/lock.mdb --exclude data/mosquitto.db --exclude ".*" . ./data/
        argc = 12;
        index = 0;
        if(rsync_param.ignore_files != NULL){
            argc += 2 * rsync_param.ignore_files->nelts;
        }

        if ((argv = calloc(argc, sizeof(char *))) == NULL) {
            njt_log_error(NJT_LOG_ERR, sync_log ,0,  "alloc error");
            exit(1);
        }

        char p[6];
        njt_memzero(p, 6);
        sprintf(p, "%d", port);

        argv[index++] = "./openrsync"; // no use now
        argv[index++] = "-r";
        argv[index++] = "-t";
        argv[index++] = "-v";
        argv[index++] = "--server";
        argv[index++] = "--sender";

        //ignore files
        if(rsync_param.ignore_files != NULL){
            ignore_files = rsync_param.ignore_files->elts;
            for(i = 0; i < rsync_param.ignore_files->nelts; i++){
                argv[index++] = "--exclude";
                argv[index++] = (char *)ignore_files[i].data;
            }
        }

        // argv[6] = "--exclude";
        // argv[7] = "data.mdb";
        // argv[8] = "--exclude";
        // argv[9] = "lock.mdb";
        // argv[10] = "--exclude";
        // argv[11] = "mosquitto.db";

        // argv[12] = "--exclude";
        // argv[13] = ".*"; // for hidden files
        argv[index++] = "--address";
        argv[index++] = strdup(bind_address);
        argv[index++] = "--port";
        argv[index++] = p;

        //just used for parse
        argv[index++] = ".";
        argv[index++] = "./data/";

        // printf ("argc %d, argv: ", argc);
        // for (i = 0; i < argc; i++) {
        //     printf (" %s", argv[i]);
        // }
        // printf("\n");
        njt_start_rsync(argc, argv);
    } else if (pid > 0) {
        return pid;
    } else {
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "failed to fork rsync daemon process");
        return NJT_INVALID_PID;
    }
    
    return 0;
}


void print_mask(uint32_t mask){
    if(mask & IN_ACCESS){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_ACCESS");
    }

    if(mask & IN_MODIFY){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_MODIFY");
    }

    if(mask & IN_CLOSE_WRITE){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_CLOSE_WRITE");
    }

    if(mask & IN_CLOSE){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_CLOSE");
    }

    if(mask & IN_OPEN){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_OPEN");
    }



    if(mask & IN_CLOSE_NOWRITE){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_CLOSE_NOWRITE");
    }
    
    if(mask & IN_CREATE){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_CREATE");
    }
    
    if(mask & IN_DELETE){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_DELETE");
    }
    
    if(mask & IN_DELETE_SELF){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_DELETE_SELF");
    }
    
    if(mask & IN_MOVE_SELF){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_MOVE_SELF");
    }
    
    if(mask & IN_MOVE){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "==========mask:IN_MOVE");
    }
}

static void
njt_helper_rsync_watch_read_handler(njt_event_t *ev)
{
    u_char                        watch_buf[INOTIFY_WATCH_BUF_SIZE];
    njt_connection_t             *src;
    njt_int_t                     n = 0;
    njt_int_t                     i = 0;
    struct inotify_event         *event;
    njt_str_t                     rsyn_file;
    u_char                       *p, tmp_buf[1024];
    int                           rc;
    njt_int_t                     qos = 0;

    src = ev->data;

njt_log_error(NJT_LOG_ERR, sync_log, 0, "=======================read");
    n = read(src->fd, watch_buf, INOTIFY_WATCH_BUF_SIZE);
    njt_log_error(NJT_LOG_ERR, sync_log, 0, "=======================read2");
    njt_log_error(NJT_LOG_ERR, sync_log, 0, "=======================read n:%d", n);
    if(n < 0){
        if(errno == EAGAIN){
            njt_log_error(NJT_LOG_ERR, sync_log, 0, "rsync handler watch read event again");
            return;
        }else{
            njt_log_error(NJT_LOG_ERR, sync_log, 0, "rsync handler watch read event error");
            njt_helper_rsync_stop_inotify();
            return;
        }
    }

    if(n == 0){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "rsync handler watch read return 0 error");
        njt_helper_rsync_stop_inotify();
        return;
    }

    if(n > 0){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "rsync handler watch read data len:%d", n);
        i = 0;
        while(i < n){
            event = (struct inotify_event*)(watch_buf + i);
            if(event->len > 0){
                if(event->name[0] == '.'){

                }else{
                    njt_log_error(NJT_LOG_ERR, sync_log, 0, 
                        "rsync watch file:%s strlen(file):%d len:%d wd:%d mask:%d", 
                        event->name, strlen(event->name), event->len, event->wd, event->mask);

                    rsyn_file.data = tmp_buf;
                    p = njt_sprintf(rsyn_file.data, "{\"filename\":\"%s\"}", event->name);
                    rsyn_file.len = p - rsyn_file.data;
                    rc = njet_iot_client_sendmsg(NJT_HELPER_RSYNC_FILE_TOPIC,
                        rsyn_file.data, rsyn_file.len, qos, rsync_param.param->mdb_ctx);

                    if(rc != NJT_OK){
                        njt_log_error(NJT_LOG_ERR, sync_log, 0, "send to file topic error:%d file:%V", rc, &rsyn_file);
                    }

                    print_mask(event->mask);
                }
            }

            i += sizeof(struct inotify_event) + event->len;
        }
    }

    return;
}


void njt_helper_rsync_start_inotify()
{
    njt_uint_t  i;
    rsync_inotify_file   *watch_files;
    // enum{MASK = IN_MODIFY | IN_CREATE | IN_DELETE | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_ACCESS| IN_OPEN| IN_DELETE_SELF|IN_MOVE_SELF};
    enum{MASK = IN_DELETE | IN_CLOSE_WRITE};


    if(rsync_param.inotify_fd == -1){
        rsync_param.inotify_fd = inotify_init();
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "==============inotify init id:%d", rsync_param.inotify_fd);
        if(rsync_param.inotify_fd == -1){
            njt_log_error(NJT_LOG_ERR, sync_log, 0, "rcyn inotify init fail");
            return;
        }
    }
    
    //add all watch dir
    watch_files = rsync_param.watch_files->elts;

    for(i = 0; i < rsync_param.watch_files->nelts; i++) {
        if(watch_files[i].watch_file.len > 0){
            njt_log_error(NJT_LOG_ERR, sync_log, 0, "==============inotify add id:%d file:%s", rsync_param.inotify_fd, watch_files[i].watch_file.data);
            watch_files[i].watch_fd = inotify_add_watch(rsync_param.inotify_fd, 
                    (const char *)watch_files[i].watch_file.data, MASK);

            if(watch_files[i].watch_fd == -1){
                njt_log_error(NJT_LOG_ERR, sync_log, 0, "rcyn inotify watch file:%V error:%d str:%s", 
                    &watch_files[i].watch_file, errno, strerror(errno));
            }else{
                njt_log_error(NJT_LOG_ERR, sync_log, 0, "rcyn inotify watch file:%V wd:%d ok", &watch_files[i].watch_file, watch_files[i].watch_fd );
            }
        }
    }

    //add read event
    njt_memzero(&rsync_param.watch_rev, sizeof(njt_event_t));
    rsync_param.watch_rev.log = sync_log;
    rsync_param.watch_rev.handler = njt_helper_rsync_watch_read_handler;
    rsync_param.watch_rev.data = &rsync_param.c;
    rsync_param.watch_rev.cancelable = 1;

    rsync_param.c.log = sync_log;
    rsync_param.c.fd = rsync_param.inotify_fd;
    rsync_param.c.read = &rsync_param.watch_rev;
    rsync_param.c.recv = njt_recv;

    njt_memzero(&rsync_param.watch_wev, sizeof(njt_event_t));
    rsync_param.watch_wev.data = &rsync_param.c;
    rsync_param.watch_wev.log = sync_log;
    rsync_param.watch_wev.ready = 1;

    rsync_param.c.write = &rsync_param.watch_wev;
    rsync_param.c.recv = njt_recv;

    if (njt_event_flags & NJT_USE_CLEAR_EVENT) {
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0,"NJT_USE_CLEAR_EVENT");
        if (njt_add_event(&rsync_param.watch_rev, NJT_READ_EVENT, NJT_CLEAR_EVENT) != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, sync_log, 0, "rsync add watch event failed");
            return;
        }
    } else {
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0,"NJT_USE_LEVEL_EVENT");
        if (njt_add_event(&rsync_param.watch_rev, NJT_READ_EVENT, NJT_LEVEL_EVENT) != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, sync_log, 0, "rsync add watch event failed");
            return;
        }
    }


    rsync_param.inotify_start = 1;
    
    return;
}


void njt_helper_rsync_stop_inotify()
{
    njt_uint_t       i;
    rsync_inotify_file   *watch_files;

    if(rsync_param.inotify_fd == -1){
        njt_log_error(NJT_LOG_INFO, sync_log, 0, "rcyn inotify fd is not start");
    }else{
        //remove all watch dir
        watch_files = rsync_param.watch_files->elts;

        for(i = 0; i < rsync_param.watch_files->nelts; i++) {
            if(watch_files[i].watch_fd != -1){
                inotify_rm_watch(rsync_param.inotify_fd, watch_files[i].watch_fd);
                watch_files[i].watch_fd = -1;
                njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "rcyn inotify rm watch file:%V", &watch_files[i].watch_file);
            }
        }

        //remove inotify event
        njt_del_event(&rsync_param.watch_rev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
    }

    rsync_param.inotify_start = 0;
    rsync_param.inotify_fd = -1;

    return;
}


// njt_int_t
// njt_helper_rsync_refresh_set_timer(njt_event_handler_pt h)
// {
//     njt_event_t *ev;
//     njt_msec_t interval;

//     ev = njt_pcalloc(njt_cycle->pool, sizeof(njt_event_t));
//     if (ev == NULL) {
//         njt_log_error(NJT_LOG_CRIT, sync_log, 0, "failed to allocate refresh event");
//         exit(2);
//     }
//     ev->log = njt_cycle->log;
//     ev->handler = h;
//     ev->cancelable = 1;
//     ev->data = NULL;
//     interval = rsync_param.refresh_interval * 1000;
//     njt_add_timer(ev, interval);

//     return NJT_OK;
// }


void
njt_helper_rsync_refresh_watch_file_mtime() {
    njt_uint_t      i;
    njt_str_t      *files;
    struct stat     st;
    struct utimbuf  tbuf;
    time_t          ctime;
    char            filename[256];

    memcpy(filename, "data/", 5);
    ctime = njt_time();
    files = rsync_param.watch_files->elts;

    for(i = 0; i < rsync_param.watch_files->nelts; i++) {
        memcpy(filename+5, files[i].data, files[i].len);
        filename[5+files[i].len] = 0;
        if (stat(filename, &st) != 0) {
            continue;
        }

        // for safety, we add refresh interval twice
        if (st.st_mtime + rsync_param.refresh_interval + rsync_param.refresh_interval >= ctime ) {
            tbuf.actime = st.st_atime;
            tbuf.modtime = st.st_mtime + 1;
            utime(filename, &tbuf);
        }
    }
}


// void
// njt_helper_rsync_refresh_timer_handler(njt_event_t *ev)
// {
//     njt_msec_t interval;
//     static njt_uint_t count;
//     static njt_uint_t next_count = 100;

//     if (rsync_status->is_master) {
//         njt_helper_rsync_refresh_watch_file_mtime();
//     }
    
//     if (rsync_status->is_master == 0 && rsync_param.watch_files != NULL) {
//         if ((rsync_param.watch_files->nelts >= 10 || rsync_status->master_changed) && !rsync_status->full_sync_busy) {
//             rsync_status->full_sync_busy = 1;
//             njt_helper_rsync_client_start(NULL, rsync_param.client_max_retry);
//             count++;
//             rsync_status->master_changed = 0;
//         } else {
//             if (!rsync_status->watch_client_busy) {
//                 rsync_status->watch_client_busy = 1;
//                 njt_helper_rsync_client_start(rsync_param.watch_files, NJT_HELPER_RSYNC_TIMER_CLIENT_RETRY);
//                 count++;
//             }
//         }
//     }

//     if (count >= next_count) {
//         njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "rsync helper refresh timer execute %l times", count);
//         next_count += 100;
//     }

//     interval = rsync_param.refresh_interval * 1000;
//     if (ev->timer_set) {
//         njt_del_timer(ev);
//     }
//     njt_add_timer(ev, interval);
// }

char* concatenate_string(char* s, const char* s1)
{
    char    *ret;
    size_t   i = strlen(s);
    size_t   j = strlen(s1);

    ret = malloc(i + j + 1);
    if (ret == NULL) {
        return ret;
    }

    memcpy(ret, s, i);
    memcpy(ret+i, s1, j);

    ret[i + j] = '\0';

    return ret;
}


njt_int_t njt_helper_rsync_add_watch(const char *tmp_str, njt_flag_t is_dir){
    rsync_inotify_file  *watch_pos;
    DIR                 *dir;
    struct dirent       *entry;
    char                 filepath[1024];

    watch_pos = njt_array_push(rsync_param.watch_files);
    if(watch_pos == NULL){
        njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
            "rsync config watch path push error");
        return NJT_ERROR;
    }
    watch_pos->watch_fd = -1;
    watch_pos->watch_file.len = strlen(tmp_str);

    watch_pos->watch_file.data = njt_pcalloc(njt_cycle->pool, watch_pos->watch_file.len + 1);
    if(watch_pos->watch_file.data == NULL){
        njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
            "rsync watch config malloc error");
        return NJT_ERROR;
    }

    njt_memcpy(watch_pos->watch_file.data, tmp_str, watch_pos->watch_file.len);

    njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
            "rsync add watch file:%s", tmp_str);

    if(is_dir){
        // if has subdir, need watch all subdir
        dir = opendir(tmp_str);
        if (dir == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rsyn directory:%s open error", tmp_str);
            return NJT_ERROR;
        }

        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                njt_memzero(filepath, 1024);
                snprintf(filepath, sizeof(filepath), "%s/%s", tmp_str, entry->d_name);
                njt_helper_rsync_add_watch(filepath, 1);
            }
        }

        if (closedir(dir) == -1) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to close dir %s", tmp_str);
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_helper_rsync_parse_json(njt_cycle_t *cycle, char *conf_fn) {
    const char          *tmp_str;
    json_t              *json;
    json_error_t         error;
    json_t              *max_retry, *interval, *files, *file, *log; 
    size_t               idx;
    struct stat          st;
    njt_str_t           *ignore_pos;

    json = json_load_file(conf_fn, 0, &error);
    if (json == NULL) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "json == NULL, %s, use default configuration", conf_fn);
    }

    log = json_object_get(json, "log_file");
    if (log == NULL) {
        rsync_param.log_file = "logs/rsync.log";
    } else {
        rsync_param.log_file = strdup(json_string_value(log));
    }

    interval = json_object_get(json, "refresh_interval");
    if (interval == NULL) {
        rsync_param.refresh_interval = 10;
    } else {
        rsync_param.refresh_interval = (njt_int_t)json_integer_value(interval);
        rsync_param.refresh_interval = njt_max(5, rsync_param.refresh_interval);
    }

    max_retry = json_object_get(json, "client_max_retry");
    if (max_retry == NULL) {
        rsync_param.client_max_retry = 3;
    } else {
        rsync_param.client_max_retry = (njt_int_t)json_integer_value(max_retry);
        rsync_param.client_max_retry = njt_max(3, rsync_param.client_max_retry);
    }

    files = json_object_get(json, "watch_files");
    if (files == NULL || json_array_size(files) == 0) {
        rsync_param.watch_files = NULL;
    } else {
        njt_log_debug(NJT_LOG_NOTICE, cycle->log, 0, "parse rsync conf file watch list size '%ld' ", json_array_size(files));
        rsync_param.watch_files = njt_array_create(cycle->pool, json_array_size(files), sizeof(rsync_inotify_file));
        json_array_foreach(files, idx, file) {
            tmp_str = json_string_value(file);
            if(tmp_str == NULL || strlen(tmp_str) < 1){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch path is null, continue");
                continue;
            }
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "===============rsync config watch parse path %s", tmp_str);


            if(tmp_str[0] != '/'){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch path %s is not absolute path, continue", tmp_str);
                continue;
            }

            //add watch and subdir
            if (stat(tmp_str, &st) == 0) {
                if(S_ISDIR(st.st_mode)){
                    njt_helper_rsync_add_watch(tmp_str, 1);
                }else{
                    njt_helper_rsync_add_watch(tmp_str, 0);
                }
            }else{
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync check dir:%s stat fail", tmp_str);
            }
        }
    }

    files = json_object_get(json, "ignore_files");
    if (files == NULL || json_array_size(files) == 0) {
        rsync_param.ignore_files = NULL;
    } else {
        njt_log_debug(NJT_LOG_NOTICE, cycle->log, 0, "parse rsync conf file  list size '%ld' ", json_array_size(files));
        rsync_param.ignore_files = njt_array_create(cycle->pool, json_array_size(files), sizeof(njt_str_t));
        json_array_foreach(files, idx, file) {
            tmp_str = json_string_value(file);
            if(tmp_str == NULL || strlen(tmp_str) < 1){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config ignore path is null, continue");
                continue;
            }

            ignore_pos = njt_array_push(rsync_param.ignore_files);
            if(ignore_pos == NULL){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config ignore path push error");
                return NJT_ERROR;
            }
            ignore_pos->len = strlen(tmp_str);

            ignore_pos->data = njt_pcalloc(cycle->pool, ignore_pos->len + 1);  //last used for '\0'
            if(ignore_pos->data == NULL){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync ignore config malloc error");
                return NJT_ERROR;
            }

            njt_memcpy(ignore_pos->data, tmp_str, ignore_pos->len);
        }
    }

    njt_log_debug(NJT_LOG_NOTICE, cycle->log, 0, "parse rsync conf file '%s' successfully", conf_fn);

    json_decref(json);
    return NJT_OK;
}


static njt_int_t njt_helper_rsync_init_mqtt_process (njt_cycle_t *cycle, helper_param *param)
{
    int ret;

    njt_cycle = cycle;


    rsync_mqtt_ctx = (struct evt_ctx_t *)param->mdb_ctx;
    njet_iot_client_set_msg_callback(rsync_mqtt_ctx, (void *)rsync_msg_callback);
    // rsync_mqtt_ctx = njet_iot_client_init(prefix, localcfg, NULL, rsync_msg_callback, client_id, log, cycle);
    
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
njt_helper_rsync_start_process(njt_cycle_t *cycle, helper_param *param, njt_pid_t *rsync_pid)
{
    char       *conf_fn;
    char       *prefix;
    char        bind_address[16];
    
    conf_fn = (char*)param->conf_fullfn.data;
    njt_stream_conf_ctx_t 		*conf_ctx =NULL ;
	njt_gossip_srv_conf_t		*gscf =NULL;

    // first check gossip conf, get local ip and sync port
	conf_ctx =(njt_stream_conf_ctx_t *)cycle->conf_ctx[njt_stream_module.index];
	if (conf_ctx) 
		gscf = conf_ctx->srv_conf[njt_gossip_module.ctx_index];
	else {
		return NJT_OK;
	}
    
    if (gscf == NULL) {
		return NJT_OK;
    }

    if (gscf->node_info.sync_port == 0) {
        return  NJT_OK;
    }


    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log); // change directory to prefix
    njt_memcpy(prefix, cycle->prefix.data, cycle->prefix.len);

    if(chdir(prefix) == -1) {
        njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "chdir(%s) failed", prefix);
    }
    njt_free(prefix);

    njt_memzero(&rsync_param, sizeof(rsync_param));
    rsync_param.inotify_start = 0;
    rsync_param.inotify_fd = -1;
    rsync_param.param = param;

    if(NJT_OK != njt_helper_rsync_parse_json(cycle, conf_fn)){
        njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "parse sync config error");
        return NJT_ERROR;
    }
    njt_helper_rsync_init_log(cycle);
    njt_helper_rsync_shm_init(cycle);

    njt_memzero(bind_address, 16);
    sprintf(bind_address, "%d.%d.%d.%d", gscf->node_info.ip[0],
            gscf->node_info.ip[1], gscf->node_info.ip[2], gscf->node_info.ip[3]);
    *rsync_pid = njt_helper_rsync_daemon_start(cycle, bind_address, gscf->node_info.sync_port);
    
    njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "bind_addrss: %s, port: %d",
                    bind_address, gscf->node_info.sync_port);
    
    if(*rsync_pid == NJT_INVALID_PID) {
        return NJT_OK;
    }

    sleep(1); // for mqtt server ready
    njt_helper_rsync_init_mqtt_process(cycle, param);
    // if (rsync_param.watch_files != NULL) {
    //     njt_helper_rsync_refresh_set_timer(njt_helper_rsync_refresh_timer_handler);
    // }

    return NJT_OK;
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

            if(NJT_OK != njt_helper_rsync_start_process(cycle, &param, &rsync_daemon_pid)){
                njt_log_error(NJT_LOG_CRIT, cycle->log, 0, "rsync helper process start error");
            }else{
                if (rsync_daemon_pid == NJT_INVALID_PID) {
                    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper rsync start/reconfiguring failed, unable to start rsync daemon, possible reasons (no gossip conf or port confliction)");
                    exit(2);
                }
            }

            njt_reconfigure = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper rsync start/reconfiguring done");
            sleep(1);
        }

        cmd = param.check_cmd_fp(cycle);
        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, -1);
            if (sync_log->file->flush) {
                sync_log->file->flush(sync_log->file, cycle->log);
            }
            if (sync_log->file->fd) {
                close(sync_log->file->fd);
            }
            njt_helper_rsync_init_log(cycle);
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
