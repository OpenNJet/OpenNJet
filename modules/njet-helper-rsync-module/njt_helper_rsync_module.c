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
#include "njt_str_util.h"
#include "openrsync/extern.h"
#include "openrsync/rsync_common.h"
#include <utime.h>

extern njt_module_t  njt_gossip_module;
extern sig_atomic_t  njt_reconfigure;

#define NJT_KEEP_MASTER_CYCLE   1

#define NJT_HELPER_CMD_NO       0
#define NJT_HELPER_CMD_STOP     1
#define NJT_HELPER_CMD_RESTART  2

#define NJT_HELPER_VER          1

#define INOTIFY_WATCH_BUF_SIZE 2048

#define NJT_HELPER_RSYNC_FILE_TOPIC     "/dyn/filesync"
#define NJT_HELPER_RSYNC_NODEINFO_TOPIC "/gossip/nodeinfo"
#define NJT_HELPER_RSYNC_FILE_MODIFY    "modify"
#define NJT_HELPER_RSYNC_FILE_DEL       "del"
#define NJT_HELPER_RSYNC_FILE_ADD_DIR   "add_dir"
#define NJT_HELPER_RSYNC_FILE_RENAME_DIR   "rename_dir"
#define NJT_HELPER_RSYNC_TIMER_CLIENT_RETRY 1


#define NJT_HELPER_RSYNC_NODEINFO_MASTER_IP_FIELD "master_ip:"
#define NJT_HELPER_RSYNC_NODEINFO_LOCAL_IP_FIELD "local_ip:"
#define NJT_HELPER_RSYNC_NODEINFO_SYNC_PORT_FIELD "sync_port:"


static njt_str_t njt_helper_rsync_err_levels[] = {
    njt_null_string,
    njt_string("emerg"),
    njt_string("alert"),
    njt_string("crit"),
    njt_string("error"),
    njt_string("warn"),
    njt_string("notice"),
    njt_string("info"),
    njt_string("debug")
};


// enum{MASK = IN_MODIFY | IN_CREATE | IN_DELETE | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_ACCESS| IN_OPEN| IN_DELETE_SELF|IN_MOVE_SELF};
enum{MASK = IN_MOVE | IN_DELETE | IN_CREATE | IN_CLOSE_WRITE | IN_DELETE_SELF};

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





struct rsync_param {
    njt_int_t     refresh_interval;
    njt_int_t     client_max_retry;
    njt_array_t  *watch_dirs;
    njt_array_t  *ignore_files;
    char         *log_file;

    njt_flag_t    inotify_start;
    njt_int_t     inotify_fd;
    njt_connection_t c;
    njt_event_t   watch_rev;
    njt_event_t   watch_wev;

    //get watch file info by watch fd
    njt_lvlhsh_t    wfd_to_watchinfo;
    njt_lvlhsh_t    identifier_to_watchinfo;
    njt_pool_t      *watch_pool;

    helper_param *param;
    njt_cycle_t  *cycle;
    njt_uint_t    log_level;
} rsync_param;


static void njt_helper_rsync_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx);
static void njt_helper_rsync_loop_mqtt(njt_event_t *ev);

// void njt_helper_rsync_syn_file(njt_str_t *syn_file);
void njt_helper_rsync_syn_real_file(njt_str_t *sync_identifier, njt_str_t *sync_prefix, 
        njt_str_t *src_syn_file, njt_str_t *dst_syn_file);
void njt_helper_rsync_start_inotify();
void njt_helper_rsync_stop_inotify();
njt_int_t njt_helper_rsync_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data);
static njt_int_t njt_helper_rsync_watch_item_exist(njt_int_t watch_fd,
            rsync_inotify_file **watch_info);
static njt_int_t njt_helper_rsync_del_watch_item_from_lvlhash(njt_int_t watch_fd);
static njt_int_t njt_helper_rsync_add_watch_item_to_lvlhash(njt_int_t watch_fd,
        rsync_inotify_file *watch_info);



njt_int_t njt_helper_rsync_add_watch(njt_log_t *log, const char *tmp_str, 
        const char *identifier_str, const char * dir_prefix_str,
        njt_flag_t is_dir, njt_flag_t dyn_watch_flag, njt_helper_rsync_inotify_type i_type);

njt_shm_t               *njt_helper_rsync_shm;
njt_slab_pool_t         *njt_helper_rsync_shpool;
njt_log_t        *sync_log;
static struct evt_ctx_t *rsync_mqtt_ctx;


const njt_lvlhsh_proto_t  njt_helper_rsync_lvlhsh_proto = {
    NJT_LVLHSH_LARGE_MEMALIGN,
    njt_helper_rsync_lvlhsh_test,
    njt_lvlhsh_pool_alloc,
    njt_lvlhsh_pool_free,
};


njt_int_t
njt_helper_rsync_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data)
{
    //ignore value compare, just return ok
    return NJT_OK;
}


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

    new_log->log_level = rsync_param.log_level;
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
    rsync_inotify_file     *watch_dirs;

    pid = fork();
    if (pid < 0) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "fork failed in njt_helper_rsync start");
        return;
    }

    if (pid > 0) {
        return; // parent
    }

    if (rsync_status->is_master || rsync_param.watch_dirs == NULL) {
        exit(0);
    }

    watch_dirs = rsync_param.watch_dirs->elts;

    for(i = 0; i < rsync_param.watch_dirs->nelts; i++){
        if (rsync_status->is_master){
            break;
        }

        if(watch_dirs[i].i_type == NJT_HELPER_RSYNC_INOFIFY_TYPE_CONFIG){
            njt_helper_rsync_syn_real_file(&watch_dirs[i].watch_dir_identifier,
                &watch_dirs[i].watch_dir_prefix, &watch_dirs[i].watch_file, &watch_dirs[i].watch_file);
        }
    }

    exit(0);
}



void
njt_helper_rsync_syn_real_file(njt_str_t *sync_identifier, njt_str_t *sync_prefix, 
        njt_str_t *src_syn_file, njt_str_t *dst_syn_file){
    size_t       argc, host_len; // k,
    char       **argv, *host_addr;
    u_char      *start, *last;
    njt_int_t    index, src_index, dst_index;

    if(src_syn_file == NULL || src_syn_file->len < 1
        || dst_syn_file == NULL || dst_syn_file->len < 1){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "sync file should not be null");
        return;
    }


    if(src_syn_file->data[0] != '/'){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "sync file should must use absolute file:%V", src_syn_file);
        return;
    }

    // ./openrsync -t -r -v remote_ip:port/{file} {dst_dir}
    argc = 1 + 10;
    if ((argv = calloc(argc, sizeof(char *))) == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "calloc failed in njt_helper_rsync start");
        return;
    }

    index = 0;
    argv[index++] = "./openrsync"; // nouse now
    argv[index++] = "-t";
    argv[index++] = "-r";
    argv[index++] = "--identifier";
    argv[index++] = (char *)sync_identifier->data;
    argv[index++] = "--prefix";
    argv[index++] = (char *)sync_prefix->data;
    argv[index++] = "--del";
    argv[index++] = "-v"; // from timer handler, 

    // argv[index++] = "--exclude";
    // argv[index++] = "data1.txt";

    host_addr = njt_helper_rsync_get_host_addr(); // host_addr :    ip:port/data/
    if (host_addr == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "master_ip and port is null, return");
        goto sync_file_exit;
    } 
    host_len = strlen(host_addr);
    src_index = index;
    argv[index++] = malloc(host_len + 1 + src_syn_file->len + 1); //first 1 is more '/' and second 1 is '\0'
    if(argv[src_index] == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rsyn malloc src file error when sync");
        goto sync_file_exit;
    }
    memcpy(argv[src_index], host_addr, (size_t)host_len);
    argv[src_index][host_len] = '/';
    memcpy(argv[src_index] + host_len + 1, src_syn_file->data, src_syn_file->len);
    argv[src_index][host_len + 1 + src_syn_file->len] = 0;

    //find last '/', as dir
    start = dst_syn_file->data;
    last = dst_syn_file->data + dst_syn_file->len;
    while(last > start){
        if(*last == '/'){
            break;
        }

        last--;
    }

    dst_index = index;
    argv[index] = malloc(last - start +2);
    if(argv[dst_index] == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rsyn malloc dst dir error when sync");
        free(argv[src_index]);
        goto sync_file_exit;
    }

    memcpy(argv[dst_index], start, last - start + 1);
    argv[dst_index][last - start + 1] = 0;

    // argv[4] = strdup("192.168.40.136:8873//root/bug/njet1.0/clb/");
    njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "%s %s %s %s %s %s %s %s", argv[0], argv[1], argv[2], argv[3], argv[4],argv[5],argv[src_index], argv[dst_index]);

    int rc = njt_start_rsync(argc, argv); // 0 success, 1 failed in client, 2 failed in connection

    if ( rc != 0) {
        //todo: now just record log, and add to fail queue
        njt_log_error(NJT_LOG_ERR, sync_log, 0, 
            "rsyn error, param:%s %s %s %s %s %s", argv[0], argv[1], argv[2], argv[3], argv[src_index], argv[dst_index]);
    }

    free(argv[src_index]);
    free(argv[dst_index]);

sync_file_exit:
    if(argv != NULL){
        free(argv);
    }
}


// void
// njt_helper_rsync_syn_file(njt_str_t *syn_file){
//     size_t       argc, host_len; // k,
//     char       **argv, *host_addr;
//     u_char      *start, *last;
//     njt_int_t    index, src_index, dst_index;

//     if(syn_file == NULL || syn_file->len < 1){
//         njt_log_error(NJT_LOG_ERR, sync_log, 0, "sync file should not be null");
//         return;
//     }


//     if(syn_file->data[0] != '/'){
//         njt_log_error(NJT_LOG_ERR, sync_log, 0, "sync file should must use absolute file:%V", syn_file);
//         return;
//     }

//     // ./openrsync -t -r -v remote_ip:port/{file} {dst_dir}
//     argc = 1 + 6;
//     if ((argv = calloc(argc, sizeof(char *))) == NULL) {
//         njt_log_error(NJT_LOG_ERR, sync_log, 0, "calloc failed in njt_helper_rsync start");
//         return;
//     }

//     index = 0;
//     argv[index++] = "./openrsync"; // nouse now
//     argv[index++] = "-t";
//     argv[index++] = "-r";
//     argv[index++] = "--del";
//     argv[index++] = "-v"; // from timer handler, 

//     // argv[index++] = "--exclude";
//     // argv[index++] = "data1.txt";

//     host_addr = njt_helper_rsync_get_host_addr(); // host_addr :    ip:port/data/
//     if (host_addr == NULL) {
//         njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "master_ip and port is null, return");
//         goto sync_file_exit;
//     } 
//     host_len = strlen(host_addr);
//     src_index = index;
//     argv[index++] = malloc(host_len + 1 + syn_file->len + 1); //first 1 is more '/' and second 1 is '\0'
//     if(argv[src_index] == NULL){
//         njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rsyn malloc src file error when sync");
//         goto sync_file_exit;
//     }
//     memcpy(argv[src_index], host_addr, (size_t)host_len);
//     argv[src_index][host_len] = '/';
//     memcpy(argv[src_index] + host_len + 1, syn_file->data, syn_file->len);
//     argv[src_index][host_len + 1 + syn_file->len] = 0;

//     //find last '/', as dir
//     start = syn_file->data;
//     last = syn_file->data + syn_file->len;
//     while(last > start){
//         if(*last == '/'){
//             break;
//         }

//         last--;
//     }

//     dst_index = index;
//     argv[index] = malloc(last - start +2);
//     if(argv[dst_index] == NULL){
//         njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rsyn malloc dst dir error when sync");
//         free(argv[src_index]);
//         goto sync_file_exit;
//     }

//     memcpy(argv[dst_index], start, last - start + 1);
//     argv[dst_index][last - start + 1] = 0;

//     // argv[4] = strdup("192.168.40.136:8873//root/bug/njet1.0/clb/");
//     njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "%s %s %s %s %s %s", argv[0], argv[1], argv[2], argv[3], argv[src_index], argv[dst_index]);

//     int rc = njt_start_rsync(argc, argv); // 0 success, 1 failed in client, 2 failed in connection

//     if ( rc != 0) {
//         //todo: now just record log, and add to fail queue
//         njt_log_error(NJT_LOG_ERR, sync_log, 0, 
//             "rsyn error, param:%s %s %s %s %s %s", argv[0], argv[1], argv[2], argv[3], argv[src_index], argv[dst_index]);
//     }

//     free(argv[src_index]);
//     free(argv[dst_index]);

// sync_file_exit:
//     if(argv != NULL){
//         free(argv);
//     }
// }

void
njt_helper_rsync_client_start(njt_str_t * sync_identifier, njt_str_t *sync_prefix,
        njt_str_t *src_syn_file, njt_str_t *dst_syn_file)
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

    njt_helper_rsync_syn_real_file(sync_identifier, sync_prefix, src_syn_file, dst_syn_file);

    exit(0);
}


njt_int_t njt_helper_rsync_nodeinfo_get_field(njt_str_t origin_str,
		njt_str_t field_str, njt_str_t *value_str)
{
    u_char          *pfs,*pvs,*pc1;

    if (origin_str.len < field_str.len
		||origin_str.len <= 0 || field_str.len <= 0){
		return NJT_ERROR;
	}
    
    pfs = njt_strstrn(origin_str.data, (char *)field_str.data, field_str.len - 1);
    if (pfs == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing nodeinfo failed, msg:%V parse:%V", &origin_str, &field_str);
		return NJT_ERROR;
	}

    pvs = pfs + field_str.len;
    if (pvs >= origin_str.data + origin_str.len) {
		return NJT_ERROR;
	}

    for (pc1 = pvs; pc1 < origin_str.data + origin_str.len && (*pc1 == ' ' || *pc1 == '{'); pc1++);
    pvs = pc1;
    for (pc1 = pvs; pc1 < origin_str.data + origin_str.len && *pc1 != ',' && *pc1 != '}'; pc1++);

    value_str->data = pvs;
    value_str->len = pc1 - pvs;

    return NJT_OK;    
}


void
njt_helper_rsync_master_change_handler(u_char *cmsg, njt_int_t msg_len)
{
    njt_str_t   origin_str, parse_str;
    njt_str_t   master_ip, local_ip, rsync_port;
    njt_int_t   p;
    njt_str_t   new_host;

    // example msg  master_ip:192.168.40.117,local_ip:192.168.40.117,sync_port:0,ctrl_port:28081

    origin_str.data = cmsg;
    origin_str.len = msg_len;

    //get masterip
    parse_str.data = (u_char *)NJT_HELPER_RSYNC_NODEINFO_MASTER_IP_FIELD;
    parse_str.len = njt_strlen(NJT_HELPER_RSYNC_NODEINFO_MASTER_IP_FIELD);
    if(NJT_ERROR == njt_helper_rsync_nodeinfo_get_field(origin_str,
			parse_str, &master_ip)){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing master ip failed, msg:%V", &origin_str);
        goto failed;
    }

    //get localip
    parse_str.data = (u_char *)NJT_HELPER_RSYNC_NODEINFO_LOCAL_IP_FIELD;
    parse_str.len = njt_strlen(NJT_HELPER_RSYNC_NODEINFO_LOCAL_IP_FIELD);
    if(NJT_ERROR == njt_helper_rsync_nodeinfo_get_field(origin_str,
			parse_str, &local_ip)){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing local ip failed, msg:%V", &origin_str);
        goto failed;
    }

    //get sync port
    parse_str.data = (u_char *)NJT_HELPER_RSYNC_NODEINFO_SYNC_PORT_FIELD;
    parse_str.len = njt_strlen(NJT_HELPER_RSYNC_NODEINFO_SYNC_PORT_FIELD);
    if(NJT_ERROR == njt_helper_rsync_nodeinfo_get_field(origin_str,
			parse_str, &rsync_port)){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing sync port failed, msg:%V", &origin_str);
        goto failed;
    }

    p = njt_atoi(rsync_port.data, rsync_port.len);
    if(p == NJT_ERROR){
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing sync port failed, msg:%V", &origin_str);
        goto failed;
    }

    if(master_ip.len == local_ip.len &&
        njt_strncmp(master_ip.data, local_ip.data, master_ip.len) == 0){
        rsync_status->is_master = 1;
    }else{
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
    new_host.len = master_ip.len + rsync_port.len + 1;  //addtional ':'
    new_host.data = njt_pcalloc(njt_cycle->pool, new_host.len + 1);  //last used for '\0'
    if (new_host.data == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "new host malloc error");
        return;
    }
    njt_snprintf(new_host.data, new_host.len + 1, "%V:%V", &master_ip, &rsync_port);

    // njt_sprintf(new_host_test.data, "%s:%d//root/bug/njet1.0/clb/", mip, rsync_status->port);

    njt_shmtx_lock(&njt_helper_rsync_shpool->mutex);
    njt_memzero(rsync_status->master_url, 1024);
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
    njt_str_t           src_syn_file, dst_syn_file, sync_identifier, sync_prefix;
    json_t              *root, *filename, *action, *prefix, *identifier;
    json_error_t        jerror;
    const char          *fname, *action_str, *prefix_str, *identifier_str;
    struct stat         st;
    u_char              real_filename_buf[2048];
    u_char              *end_char;
    rsync_inotify_file *watch_info;

    if (rsync_status->is_master) {
        njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "I AM MASTER, DO nothing");
        return; // msster do nothing 
    }

    
    root = json_loads(msg, 0, &jerror);
    if (root == NULL)  {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "json root is null, msg: '%s'", msg);
        return;
    }

    action = json_object_get(root, "action");
    if (action == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "action is null, msg: '%s'", msg);
        return;
    }
    action_str = json_string_value(action);
    if (action_str == NULL || njt_strlen(action_str) < 1) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "action_str is null, msg: '%s'", msg);
        return;
    }

    prefix = json_object_get(root, "prefix");
    if (prefix == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "prefix is null, msg: '%s'", msg);
        return;
    }
    prefix_str = json_string_value(prefix);
    if (prefix_str == NULL || njt_strlen(prefix_str) <1) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "prefix_str is null, msg: '%s'", msg);
        return;
    }

    identifier = json_object_get(root, "identifier");
    if (identifier == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "identifier is null, msg: '%s'", msg);
        return;
    }
    identifier_str = json_string_value(identifier);
    if (identifier_str == NULL || njt_strlen(identifier_str) < 1) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "identifier_str is null, msg: '%s'", msg);
        return;
    }

    filename = json_object_get(root, "filename");
    if (filename == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "filename is null, msg: '%s'", msg);
        return;
    }
    fname = json_string_value(filename);
    if (fname == NULL || njt_strlen(fname) < 1) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "fname is null, msg: '%s'", fname);
        return;
    }

    //get local watch info by idenfier
    sync_identifier.data = (u_char *)identifier_str;
    sync_identifier.len = njt_strlen(identifier_str);
    if(NJT_OK != njt_helper_rsync_watch_identifier_exist(sync_identifier, &watch_info)){
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "identifier:%V is not exist in local", &sync_identifier);
        return;
    }


    sync_prefix.data = (u_char *)prefix_str;
    sync_prefix.len = njt_strlen(prefix_str);

    src_syn_file.data = (u_char *)fname;
    src_syn_file.len = njt_strlen(fname);

    njt_memzero(real_filename_buf, 2048);
    end_char = njt_snprintf(real_filename_buf, 2048, "%V/%s", &watch_info->watch_dir_prefix, fname + njt_strlen(prefix_str));
    dst_syn_file.data = real_filename_buf;
    dst_syn_file.data[2047] = 0;
    dst_syn_file.len = end_char - real_filename_buf;
    
    if(njt_strcmp(action_str, NJT_HELPER_RSYNC_FILE_MODIFY) == 0){
        njt_log_debug(NJT_LOG_DEBUG, sync_log, 0, 
            "rsync helper syn src_filename:%V dst_filename:%V syn_identifier:%V  sync_prefix:%V",
            &src_syn_file, &dst_syn_file, &sync_identifier, &sync_prefix);
        njt_helper_rsync_client_start(&sync_identifier, &sync_prefix, &src_syn_file, &dst_syn_file);
    }else if(njt_strcmp(action_str, NJT_HELPER_RSYNC_FILE_DEL) == 0){
        njt_log_debug(NJT_LOG_DEBUG, sync_log, 0, "rsync helper del filename or dir:%V", &dst_syn_file);

        if (stat((const char*)dst_syn_file.data, &st) == 0) {
            if(S_ISDIR(st.st_mode)){
                njt_log_debug(NJT_LOG_DEBUG, sync_log, 0, "rsync helper del dir:%V", &dst_syn_file);
                if (rmdir((const char*)dst_syn_file.data) == -1) {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to rm dir:%V", &dst_syn_file);
                }
            }else{
                if (remove((const char*)dst_syn_file.data) == -1) {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to rm file:%V", &dst_syn_file);
                }
            }
        }
    }else if(njt_strcmp(action_str, NJT_HELPER_RSYNC_FILE_ADD_DIR) == 0){
        njt_log_debug(NJT_LOG_DEBUG, sync_log, 0, "rsync helper add dir:%V", &dst_syn_file);

        if(NJT_OK != njt_mkdir_recursive(dst_syn_file)){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to add dir:%V", &dst_syn_file);
        }
    }

    json_decref(root);
}

njt_int_t
njt_helper_rsync_daemon_stop(njt_pid_t pid)
{
    int            signo; 
    njt_err_t      err;
    // char*          path = "./data";
    // struct dirent *entry;
    // DIR           *dir;

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

    //todo remove possible hidden files of all watch file
    // dir = opendir(path);
    // if (dir == NULL) {
    //     njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "./data directory is null");
    //     return NJT_ERROR;
    // }

    // while ((entry = readdir(dir)) != NULL) {
    //     if (entry->d_type == DT_DIR) {
    //         continue;
    //     }

    //     if (entry->d_name[0] == '.') {
    //         char filepath[300];
    //         snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
    //         filepath[299] = 0;
    //         if (remove(filepath) == -1) {
    //             njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to rm hidden file %s", filepath);
    //             return NJT_ERROR;
    //         }
    //         njt_log_debug(NJT_LOG_DEBUG, njt_cycle->log, 0,  "Deleted: %s\n", filepath);
    //     }
    // }

    // if (closedir(dir) == -1) {
    //     njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to close dir %s", path);
    //     return NJT_ERROR;
    // }

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
    njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "mqtt msg received '%s'", msg);

    if (njt_exiting || njt_terminate) {
        //when process is exiting or terminate, skip msg processing
        njt_log_error(NJT_LOG_INFO, sync_log, 0, "process is existing, skip kv handling");
        return NJT_OK;
    }

    if (topic_l == node_topic_l && 0 == memcmp(topic, NJT_HELPER_RSYNC_NODEINFO_TOPIC, node_topic_l)) {
        njt_helper_rsync_master_change_handler((u_char *)msg, msg_len);
    }

    if (topic_l == file_topic_l && 0 == memcmp(topic, NJT_HELPER_RSYNC_FILE_TOPIC, file_topic_l)) {
        njt_helper_rsync_file_change_handler(msg, msg_len);
    }

    return NJT_OK;
}

njt_pid_t
njt_helper_rsync_daemon_start(njt_cycle_t *cycle, char *bind_address, int port)
{
    njt_uint_t  argc; // , i;
    char      **argv;
    njt_pid_t   pid;
    njt_uint_t  i, index;
    char       *name = "rsync server daemon";
    njt_str_t   *ignore_files;


    pid = fork();
    if (pid == 0) {
        njt_setproctitle(name);

        // ./openrsync -t -r -vvvv --sender --server --exclude data/data.mdb --exclude data/lock.mdb --exclude data/mosquitto.db --exclude ".*" . ./data/
        argc = 15;
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
        argv[index++] = "--del";
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

        argv[index++] = "--exclude";
        argv[index++] = ".*"; // for hidden files
        argv[index++] = "--address";
        argv[index++] = strdup(bind_address);
        argv[index++] = "--port";
        argv[index++] = p;

        //just used for parse
        argv[index++] = ".";
        argv[index++] = "./data/";

        // printf ("argc %d, argv: ", argc);
        for (i = 0; i < argc; i++) {
            njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "i:%d argv:%s", i, argv[i]);
        }
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
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_ACCESS");
    }

    if(mask & IN_MODIFY){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_MODIFY");
    }

    if(mask & IN_CLOSE_WRITE){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_CLOSE_WRITE");
    }

    if(mask & IN_CLOSE){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_CLOSE");
    }

    if(mask & IN_OPEN){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_OPEN");
    }

    if(mask & IN_CLOSE_NOWRITE){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_CLOSE_NOWRITE");
    }
    
    if(mask & IN_CREATE){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_CREATE");
    }
    
    if(mask & IN_DELETE){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_DELETE");
    }
    
    if(mask & IN_DELETE_SELF){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_DELETE_SELF");
    }
    
    if(mask & IN_MOVE_SELF){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_MOVE_SELF");
    }
    
    if(mask & IN_MOVE){
        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "==========mask:IN_MOVE");
    }
}

njt_int_t
njt_helper_rsync_is_ignore_file(char *name){
    njt_uint_t      i;
    njt_str_t       *ignore_files;

    if(name == NULL){
        return NJT_OK;
    }

    if(rsync_param.ignore_files != NULL){
        ignore_files = rsync_param.ignore_files->elts;
        for(i = 0; i < rsync_param.ignore_files->nelts; i++){
            if(njt_strcmp(name, ignore_files[i].data) == 0){
                return NJT_DECLINED;
            }
        }
    }

    return NJT_OK;
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
    rsync_inotify_file           *watch_info;
    struct stat                   st;
    njt_flag_t                    is_dir;

    src = ev->data;

    n = read(src->fd, watch_buf, INOTIFY_WATCH_BUF_SIZE);
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
        i = 0;
        while(i < n){
            event = (struct inotify_event*)(watch_buf + i);
            if(event->len > 0){
                if(event->name[0] == '.'){
                }else{
                    njt_log_error(NJT_LOG_DEBUG, sync_log, 0, 
                        "rsync watch file:%s strlen(file):%d len:%d wd:%d mask:%d", 
                        event->name, strlen(event->name), event->len, event->wd, event->mask);

                    //todo get watch file by wd
                    if(NJT_OK != njt_helper_rsync_watch_item_exist(event->wd, &watch_info)){
                        i += sizeof(struct inotify_event) + event->len;
                        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "watch fd:%d is not exist", event->wd);
                        continue;
                    }

                    rsyn_file.data = tmp_buf;

                    is_dir = 0;
                    p = njt_sprintf(rsyn_file.data, "%V/%s", &watch_info->watch_file, event->name);
                    rsyn_file.len = p - rsyn_file.data;
                    if(rsyn_file.len >= 1024){
                        njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "watch file too long:%V", &rsyn_file);
                        i += sizeof(struct inotify_event) + event->len;
                        continue;
                    }else{
                        rsyn_file.data[rsyn_file.len] = 0;
                        rsyn_file.len++;

                        if (stat((const char *)rsyn_file.data, &st) == 0) {
                            if(S_ISDIR(st.st_mode)){
                                is_dir = 1;
                            }else{
                                //compare ignore files
                                if(NJT_DECLINED == njt_helper_rsync_is_ignore_file(event->name)){
                                    njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "ignore:%V", &rsyn_file);
                                    i += sizeof(struct inotify_event) + event->len;
                                    continue;
                                }
                            }
                        }else{
                            if((event->mask & IN_DELETE) || (event->mask & IN_DELETE_SELF)){
                            }else{
                                njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "stat error, ignore:%V", &rsyn_file);
                                i += sizeof(struct inotify_event) + event->len;
                                continue;
                            }
                        }
                    }

                    if(event->mask & IN_CLOSE_WRITE){
                        //only process add file or modify file
                        p = njt_sprintf(rsyn_file.data, "{\"action\":\"%s\", \"identifier\":\"%V\", \"prefix\":\"%V\", \"filename\":\"%V/%s\"}", 
                            NJT_HELPER_RSYNC_FILE_MODIFY, &watch_info->watch_dir_identifier, &watch_info->watch_dir_prefix,
                            &watch_info->watch_file, event->name);
                    }else if(event->mask & IN_MOVE){
                        if(is_dir){
                            //rename dir, need more thing todo
                            njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "not support rename dir watch:%V", &rsyn_file);
                            i += sizeof(struct inotify_event) + event->len;
                            continue;
                        }else{
                            p = njt_sprintf(rsyn_file.data, "{\"action\":\"%s\", \"identifier\":\"%V\", \"prefix\":\"%V\", \"filename\":\"%V/%s\"}", 
                                NJT_HELPER_RSYNC_FILE_MODIFY, &watch_info->watch_dir_identifier, &watch_info->watch_dir_prefix,
                                &watch_info->watch_file, event->name);
                        }
                    }else if(event->mask & IN_CREATE){
                        //only process add dir
                        if(is_dir){
                            //only add current dir, not add subdir
                            njt_helper_rsync_add_watch(sync_log, (const char *)rsyn_file.data, (const char *)watch_info->watch_dir_identifier.data,
                                (const char *)watch_info->watch_dir_prefix.data, 1, 1, NJT_HELPER_RSYNC_INOFIFY_TYPE_INTERNAL);
                        
                            p = njt_sprintf(rsyn_file.data, "{\"action\":\"%s\", \"identifier\":\"%V\", \"prefix\":\"%V\", \"filename\":\"%V/%s\"}", 
                                NJT_HELPER_RSYNC_FILE_ADD_DIR, &watch_info->watch_dir_identifier, &watch_info->watch_dir_prefix,
                                &watch_info->watch_file, event->name);
                        }

                        i += sizeof(struct inotify_event) + event->len;
                        continue;
                    }
                    else if(event->mask & IN_DELETE){
                        p = njt_sprintf(rsyn_file.data, "{\"action\":\"%s\",  \"identifier\":\"%V\", \"prefix\":\"%V\", \"filename\":\"%V/%s\"}",
                            NJT_HELPER_RSYNC_FILE_DEL, &watch_info->watch_dir_identifier, &watch_info->watch_dir_prefix,
                            &watch_info->watch_file, event->name);
                    }else if(event->mask & IN_DELETE_SELF){
                        p = njt_sprintf(rsyn_file.data, "{\"action\":\"%s\",  \"identifier\":\"%V\", \"prefix\":\"%V\", \"filename\":\"%V\"}",
                            NJT_HELPER_RSYNC_FILE_DEL, &watch_info->watch_dir_identifier, &watch_info->watch_dir_prefix,
                            &watch_info->watch_file);
                    }else{
                        i += sizeof(struct inotify_event) + event->len;
                        continue;
                    }

                    rsyn_file.len = p - rsyn_file.data;
                    rc = njet_iot_client_sendmsg(NJT_HELPER_RSYNC_FILE_TOPIC,
                        rsyn_file.data, rsyn_file.len, qos, rsync_param.param->mdb_ctx);

                    if(rc == -1){
                        njt_log_error(NJT_LOG_ERR, sync_log, 0, "send to file:%V topic error:%d", &rsyn_file, rc);
                    }else{
                        njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "send to file:%V topic ok", &rsyn_file);
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
    rsync_inotify_file   *watch_dirs;

    if(rsync_param.inotify_fd == -1){
        rsync_param.inotify_fd = inotify_init();
        njt_log_error(NJT_LOG_INFO, sync_log, 0, "rsync inotify init id:%d", rsync_param.inotify_fd);
        if(rsync_param.inotify_fd == -1){
            njt_log_error(NJT_LOG_ERR, sync_log, 0, "rcyn inotify init fail");
            return;
        }
    }
    
    if(rsync_param.watch_dirs == NULL){
        return;
    }

    //add all watch dir
    watch_dirs = rsync_param.watch_dirs->elts;

    for(i = 0; i < rsync_param.watch_dirs->nelts; i++) {
        if(watch_dirs[i].watch_file.len > 0){
            njt_log_error(NJT_LOG_DEBUG, sync_log, 0, "rsync inotify add id:%d dir:%s", rsync_param.inotify_fd, watch_dirs[i].watch_file.data);
            watch_dirs[i].watch_fd = inotify_add_watch(rsync_param.inotify_fd, 
                    (const char *)watch_dirs[i].watch_file.data, MASK);

            if(watch_dirs[i].watch_fd == -1){
                njt_log_error(NJT_LOG_ERR, sync_log, 0, "rcyn inotify watch dir:%V error:%d str:%s", 
                    &watch_dirs[i].watch_file, errno, strerror(errno));
            }else{
                njt_helper_rsync_add_watch_item_to_lvlhash(watch_dirs[i].watch_fd, &watch_dirs[i]);
                njt_log_error(NJT_LOG_INFO, sync_log, 0, "rcyn inotify watch dir:%V wd:%d ok", &watch_dirs[i].watch_file, watch_dirs[i].watch_fd );

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
    rsync_inotify_file   *watch_dirs;

    if(rsync_param.inotify_fd == -1){
        njt_log_error(NJT_LOG_INFO, sync_log, 0, "rcyn inotify fd is not start");
    }else{
        if(rsync_param.watch_dirs != NULL){
            //remove all watch dir
            watch_dirs = rsync_param.watch_dirs->elts;

            for(i = 0; i < rsync_param.watch_dirs->nelts; i++) {
                if(watch_dirs[i].watch_fd != -1){
                    inotify_rm_watch(rsync_param.inotify_fd, watch_dirs[i].watch_fd);
                    

                    njt_helper_rsync_del_watch_item_from_lvlhash(watch_dirs[i].watch_fd);
                    
                    if(watch_dirs[i].i_type == NJT_HELPER_RSYNC_INOFIFY_TYPE_CONFIG){
                        // njt_helper_rsync_del_watch_identifier_from_lvlhash(watch_dirs[i].watch_dir_identifier);
                        //config watch should exist for long time
                    }else{
                        //free  watch_file
                        if(watch_dirs[i].watch_file.len > 0){
                            njt_pfree(rsync_param.watch_pool, watch_dirs[i].watch_file.data);
                        }

                        //free  watch_dir_identifier
                        if(watch_dirs[i].watch_dir_identifier.len > 0){
                            njt_pfree(rsync_param.watch_pool, watch_dirs[i].watch_dir_identifier.data);
                        }

                        //free  watch_dir_prefix
                        if(watch_dirs[i].watch_dir_prefix.len > 0){
                            njt_pfree(rsync_param.watch_pool, watch_dirs[i].watch_dir_prefix.data);
                        }

                        njt_str_null(&watch_dirs[i].watch_file);
                        njt_str_null(&watch_dirs[i].watch_dir_prefix);
                        njt_str_null(&watch_dirs[i].watch_dir_identifier);
                    }

                    watch_dirs[i].watch_fd = -1;
                    njt_log_error(NJT_LOG_INFO, sync_log, 0, "rcyn inotify rm watch file:%V", &watch_dirs[i].watch_file);
                }
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


// void
// njt_helper_rsync_refresh_watch_file_mtime() {
//     njt_uint_t      i;
//     njt_str_t      *files;
//     struct stat     st;
//     struct utimbuf  tbuf;
//     time_t          ctime;
//     char            filename[256];

//     memcpy(filename, "data/", 5);
//     ctime = njt_time();
//     files = rsync_param.watch_dirs->elts;

//     for(i = 0; i < rsync_param.watch_dirs->nelts; i++) {
//         memcpy(filename+5, files[i].data, files[i].len);
//         filename[5+files[i].len] = 0;
//         if (stat(filename, &st) != 0) {
//             continue;
//         }

//         // for safety, we add refresh interval twice
//         if (st.st_mtime + rsync_param.refresh_interval + rsync_param.refresh_interval >= ctime ) {
//             tbuf.actime = st.st_atime;
//             tbuf.modtime = st.st_mtime + 1;
//             utime(filename, &tbuf);
//         }
//     }
// }


// void
// njt_helper_rsync_refresh_timer_handler(njt_event_t *ev)
// {
//     njt_msec_t interval;
//     static njt_uint_t count;
//     static njt_uint_t next_count = 100;

//     if (rsync_status->is_master) {
//         njt_helper_rsync_refresh_watch_file_mtime();
//     }
    
//     if (rsync_status->is_master == 0 && rsync_param.watch_dirs != NULL) {
//         if ((rsync_param.watch_dirs->nelts >= 10 || rsync_status->master_changed) && !rsync_status->full_sync_busy) {
//             rsync_status->full_sync_busy = 1;
//             njt_helper_rsync_client_start(NULL, rsync_param.client_max_retry);
//             count++;
//             rsync_status->master_changed = 0;
//         } else {
//             if (!rsync_status->watch_client_busy) {
//                 rsync_status->watch_client_busy = 1;
//                 njt_helper_rsync_client_start(rsync_param.watch_dirs, NJT_HELPER_RSYNC_TIMER_CLIENT_RETRY);
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


njt_int_t njt_helper_rsync_add_watch(njt_log_t *log, const char *tmp_str, const char *identifier_str, const char *dir_prefix_str,
        njt_flag_t is_dir, njt_flag_t dyn_watch_flag, njt_helper_rsync_inotify_type i_type){
    rsync_inotify_file  *watch_pos;
    DIR                 *dir;
    struct dirent       *entry;
    char                 filepath[2048];
    njt_str_t            rsyn_file;
    u_char              *p;
    int                  rc;
    njt_int_t            qos = 0;

    watch_pos = njt_array_push(rsync_param.watch_dirs);
    if(watch_pos == NULL){
        njt_log_error(NJT_LOG_NOTICE, log, 0,
            "rsync config watch path push error");
        return NJT_ERROR;
    }

    watch_pos->i_type = i_type;
    watch_pos->watch_fd = -1;

    watch_pos->watch_file.len = strlen(tmp_str);
    watch_pos->watch_file.data = njt_pcalloc(rsync_param.watch_pool, watch_pos->watch_file.len + 1);
    if(watch_pos->watch_file.data == NULL){
        njt_log_error(NJT_LOG_NOTICE, log, 0,
            "rsync watch config malloc error dir:%s", tmp_str);
        return NJT_ERROR;
    }
    njt_memcpy(watch_pos->watch_file.data, tmp_str, watch_pos->watch_file.len);

    watch_pos->watch_dir_identifier.len = strlen(identifier_str);
    watch_pos->watch_dir_identifier.data = njt_pcalloc(rsync_param.watch_pool, watch_pos->watch_dir_identifier.len + 1);
    if(watch_pos->watch_dir_identifier.data == NULL){
        njt_log_error(NJT_LOG_NOTICE, log, 0,
            "rsync watch config malloc error dir:%s", identifier_str);
        return NJT_ERROR;
    }
    njt_memcpy(watch_pos->watch_dir_identifier.data, identifier_str, watch_pos->watch_dir_identifier.len);

    watch_pos->watch_dir_prefix.len = strlen(dir_prefix_str);
    watch_pos->watch_dir_prefix.data = njt_pcalloc(rsync_param.watch_pool, watch_pos->watch_dir_prefix.len + 1);
    if(watch_pos->watch_dir_prefix.data == NULL){
        njt_log_error(NJT_LOG_NOTICE, log, 0,
            "rsync watch config malloc error dir:%s", dir_prefix_str);
        return NJT_ERROR;
    }
    njt_memcpy(watch_pos->watch_dir_prefix.data, dir_prefix_str, watch_pos->watch_dir_prefix.len);

    njt_log_error(NJT_LOG_NOTICE, log, 0,
            "rsync add watch file:%V  identifier:%V prefix:%V",
            &watch_pos->watch_file, &watch_pos->watch_dir_identifier,
            &watch_pos->watch_dir_prefix);
            
    if(i_type == NJT_HELPER_RSYNC_INOFIFY_TYPE_CONFIG){
        njt_helper_rsync_add_watch_identifier_to_lvlhash(watch_pos->watch_dir_identifier, watch_pos);
        njt_log_error(NJT_LOG_INFO, log, 0, "rcyn inotify watch real prefix:%V ok", 
            &watch_pos->watch_file);
    }

    if(dyn_watch_flag){
        //add inodify
        watch_pos->watch_fd = inotify_add_watch(rsync_param.inotify_fd, 
                (const char *)watch_pos->watch_file.data, MASK);

        if(watch_pos->watch_fd == -1){
            njt_log_error(NJT_LOG_ERR, log, 0, "rcyn inotify watch file:%V error:%d str:%s", 
                &watch_pos->watch_file, errno, strerror(errno));
        }else{
            njt_helper_rsync_add_watch_item_to_lvlhash(watch_pos->watch_fd, watch_pos);

            //sendto topic
            rsyn_file.data = (u_char *)filepath;
            p = njt_sprintf(rsyn_file.data, "{\"action\":\"%s\", \"identifier\":\"%s\", \"prefix\":\"%s\", \"filename\":\"%s\"}",
                    NJT_HELPER_RSYNC_FILE_ADD_DIR, identifier_str, dir_prefix_str, tmp_str);

            rsyn_file.len = p - rsyn_file.data;
            rc = njet_iot_client_sendmsg(NJT_HELPER_RSYNC_FILE_TOPIC,
                rsyn_file.data, rsyn_file.len, qos, rsync_param.param->mdb_ctx);

            if(rc == -1){
                njt_log_error(NJT_LOG_ERR, log, 0, "dyn watch, send to dir:%V topic error:%d", &rsyn_file, rc);
            }else{
                njt_log_error(NJT_LOG_INFO, log, 0, "dyn watch, send to dir:%V topic ok", &rsyn_file);
            }

            njt_log_error(NJT_LOG_INFO, log, 0, "dyn watch, rcyn inotify watch dir:%V wd:%d ok",
                &watch_pos->watch_file, watch_pos->watch_fd );
        }

        //list all has exist files
        dir = opendir(tmp_str);
        if (dir != NULL) {
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type == DT_REG && entry->d_name[0] != '.') {
                    njt_memzero(filepath, 2048);
                    rsyn_file.data = (u_char *)filepath;
                    p = njt_sprintf(rsyn_file.data, "{\"action\":\"%s\", \"identifier\":\"%s\", \"prefix\":\"%s\", \"filename\":\"%s/%s\"}", 
                        NJT_HELPER_RSYNC_FILE_MODIFY, identifier_str, dir_prefix_str, tmp_str, entry->d_name);

                    rsyn_file.len = p - rsyn_file.data;
                    rc = njet_iot_client_sendmsg(NJT_HELPER_RSYNC_FILE_TOPIC,
                        rsyn_file.data, rsyn_file.len, qos, rsync_param.param->mdb_ctx);

                    if(rc == -1){
                        njt_log_error(NJT_LOG_ERR, log, 0, "dyn watch, send to file:%V topic error:%d", &rsyn_file, rc);
                    }else{
                        njt_log_error(NJT_LOG_DEBUG, log, 0, "dyn watch, send to file:%V topic ok", &rsyn_file);
                    }
                }
            }

            if (closedir(dir) == -1) {
                njt_log_error(NJT_LOG_ERR, log, 0, "failed to close dir %s", tmp_str);
                // return NJT_ERROR;
            }
        }else{
            njt_log_error(NJT_LOG_ERR, log, 0, "rsyn directory:%s open error", tmp_str);
        }
    }

    if(is_dir){
        // if has subdir, need watch all subdir
        dir = opendir(tmp_str);
        if (dir == NULL) {
            njt_log_error(NJT_LOG_ERR, log, 0, "rsyn directory:%s open error", tmp_str);
            return NJT_ERROR;
        }

        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
                njt_memzero(filepath, 2048);
                snprintf(filepath, sizeof(filepath), "%s/%s", tmp_str, entry->d_name);
                njt_helper_rsync_add_watch(log, filepath, identifier_str, dir_prefix_str, 1, dyn_watch_flag, NJT_HELPER_RSYNC_INOFIFY_TYPE_INTERNAL);
            }
        }

        if (closedir(dir) == -1) {
            njt_log_error(NJT_LOG_ERR, log, 0, "failed to close dir %s", tmp_str);
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}



njt_int_t njt_helper_rsync_filter_data_dir(njt_cycle_t *cycle, const char *tmp_str){
    u_char                  tmp_buf[1024], *end_char;
    njt_str_t               cmp_str;
    size_t                  tmp_str_len = (size_t)strlen(tmp_str);

    //simple compare
    njt_memzero(tmp_buf, 1024);
    if(cycle->prefix.data[cycle->prefix.len - 1] == '/'){
        end_char = njt_snprintf(tmp_buf, 1024, "%Vdata", &cycle->prefix);
    }else{
        end_char = njt_snprintf(tmp_buf, 1024, "%V/data", &cycle->prefix);
    }
    
    cmp_str.data = tmp_buf;
    cmp_str.len = end_char - tmp_buf;

    //compare prefix
    if(tmp_str_len <= cmp_str.len){
        if(njt_strncmp(tmp_str, cmp_str.data, tmp_str_len) == 0){
            if(tmp_str_len == cmp_str.len || tmp_str[tmp_str_len -1] == '/'){
                return NJT_DECLINED;
            }

            if(cmp_str.data[tmp_str_len] == '/'){
                return NJT_DECLINED;
            }
        }
    }else{
        if(tmp_str[cmp_str.len] == '/' && tmp_str_len == (cmp_str.len + 1)){
            return NJT_DECLINED;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_helper_rsync_parse_json(njt_cycle_t *cycle, char *conf_fn) {
    char                *log_level_str;
    json_t              *json;
    json_error_t         error;
    json_t              *max_retry, *interval, *files, *file, *log, *log_level; 
    size_t               idx;
    struct stat          st;
    // njt_str_t           *ignore_pos;
    njt_str_t            tmp_dir_str;
    njt_uint_t           n, found;
    json_t              *identifier, *dir_prefix, *watch_dir;
    char                *identifier_str, *dir_prefix_str, *watch_dir_str;


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

    log_level = json_object_get(json, "log_level");
    if (log_level == NULL) {
        rsync_param.log_level = NJT_LOG_DEBUG;
    } else {
        found = 0;
        log_level_str = strdup(json_string_value(log_level));
        for (n = 1; n <= NJT_LOG_DEBUG; n++) {
            if (njt_strcmp(log_level_str, njt_helper_rsync_err_levels[n].data) == 0) {
                rsync_param.log_level = n;
                found = 1;
                break;
            }
        }

        if(!found){
            rsync_param.log_level = NJT_LOG_DEBUG;
        }
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

    files = json_object_get(json, "watch_dirs");
    if (files == NULL || json_array_size(files) == 0) {
        rsync_param.watch_dirs = NULL;
    } else {
        njt_log_debug(NJT_LOG_NOTICE, cycle->log, 0, "parse rsync conf file watch list size '%ld' ", json_array_size(files));
        rsync_param.watch_dirs = njt_array_create(rsync_param.watch_pool, 4, sizeof(rsync_inotify_file));
        json_array_foreach(files, idx, file) {
            //get identifier
            identifier = json_object_get(file, "identifier");
            if (identifier == NULL) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch dir identifier is null");
                continue;
            }

            identifier_str = (char *)json_string_value(identifier);
            if(identifier_str == NULL || strlen(identifier_str) < 1){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch dir identifier is null");
                continue;
            }

            //get watch dir
            watch_dir = json_object_get(file, "dir");
            if (watch_dir == NULL) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch dir is null");
                continue;
            }

            watch_dir_str = (char *)json_string_value(watch_dir);
            if(watch_dir_str == NULL || strlen(watch_dir_str) < 1){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch dir is null");
                continue;
            }

            if(watch_dir_str[0] != '/'){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch dir:%s is not absolute path, continue", watch_dir_str);
                continue;
            }

            //get watch dir prefix
            dir_prefix = json_object_get(file, "prefix");
            if (dir_prefix == NULL) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch dir prefix is null");
                continue;
            }
            dir_prefix_str = (char *)json_string_value(dir_prefix);
            if(dir_prefix_str == NULL || strlen(dir_prefix_str) < 1){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch dir prefix is null");
                continue;
            }

            //dir prefix must be substr of watch_dir
            if(njt_strlen(watch_dir_str) < njt_strlen(dir_prefix_str)
                || 0 != njt_strncmp(dir_prefix_str, watch_dir_str, strlen(dir_prefix_str))){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config watch dir prefix:%s is not substr of dir:%s", dir_prefix_str, watch_dir_str);
                continue;
            }

            //filter {prefix}/data dir
            if(NJT_DECLINED == njt_helper_rsync_filter_data_dir(cycle, watch_dir_str)){
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                    "rsync config not support watch data path and it's root path, %s", watch_dir_str);
                continue;
            }

            //add watch and subdir
            if (stat(watch_dir_str, &st) == 0) {
                if(S_ISDIR(st.st_mode)){
                    njt_helper_rsync_add_watch(cycle->log, watch_dir_str, identifier_str, dir_prefix_str, 1, 0, NJT_HELPER_RSYNC_INOFIFY_TYPE_CONFIG);
                }else{
                    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                        "rsync config not support watch file:%s", watch_dir_str);
                    // njt_helper_rsync_add_watch(tmp_str, 0, 0, NJT_HELPER_RSYNC_INOFIFY_TYPE_CONFIG);
                }
            }else{
                njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                    "rsync check dir:%s stat fail, local create dir, and add watch", watch_dir_str);
                
                tmp_dir_str.data = (u_char *)watch_dir_str;
                tmp_dir_str.len = strlen(watch_dir_str);
                if(NJT_OK != njt_mkdir_recursive(tmp_dir_str)){
                    njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                        "rsync create dir:%V error", &tmp_dir_str);
                    continue;
                }

                //still need add to watch file, default as file add
                njt_helper_rsync_add_watch(cycle->log, watch_dir_str, identifier_str, dir_prefix_str, 1, 0, NJT_HELPER_RSYNC_INOFIFY_TYPE_CONFIG);
            }
        }
    }

    rsync_param.ignore_files = NULL;
    //not support ignore file config

    // files = json_object_get(json, "ignore_files");
    // if (files == NULL || json_array_size(files) == 0) {
    //     rsync_param.ignore_files = NULL;
    // } else {
    //     njt_log_debug(NJT_LOG_NOTICE, cycle->log, 0, "parse rsync conf file  list size '%ld' ", json_array_size(files));
    //     rsync_param.ignore_files = njt_array_create(cycle->pool, json_array_size(files), sizeof(njt_str_t));
    //     json_array_foreach(files, idx, file) {
    //         tmp_str = json_string_value(file);
    //         if(tmp_str == NULL || strlen(tmp_str) < 1){
    //             njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
    //                 "rsync config ignore path is null, continue");
    //             continue;
    //         }

    //         ignore_pos = njt_array_push(rsync_param.ignore_files);
    //         if(ignore_pos == NULL){
    //             njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
    //                 "rsync config ignore path push error");
    //             return NJT_ERROR;
    //         }
    //         ignore_pos->len = strlen(tmp_str);

    //         ignore_pos->data = njt_pcalloc(cycle->pool, ignore_pos->len + 1);  //last used for '\0'
    //         if(ignore_pos->data == NULL){
    //             njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
    //                 "rsync ignore config malloc error");
    //             return NJT_ERROR;
    //         }

    //         njt_memcpy(ignore_pos->data, tmp_str, ignore_pos->len);
    //     }
    // }

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


static njt_int_t njt_helper_rsync_watch_item_exist(njt_int_t watch_fd,
            rsync_inotify_file **watch_info){
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[50];
    u_char                                  *end;
    
    end = njt_snprintf(buff, 50, "%d", watch_fd);
    lhq.key.data = buff;
    lhq.key.len = end - buff;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_helper_rsync_lvlhsh_proto;
    lhq.pool = rsync_param.watch_pool;

    if(NJT_OK == njt_lvlhsh_find(&rsync_param.wfd_to_watchinfo, &lhq)){
        *watch_info = lhq.value;
        return NJT_OK;
    }

    return NJT_ERROR;
}


static njt_int_t njt_helper_rsync_del_watch_item_from_lvlhash(njt_int_t watch_fd){
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[50];
    u_char                                  *end;
    
    end = njt_snprintf(buff, 50, "%d", watch_fd);
    lhq.key.data = buff;
    lhq.key.len = end - buff;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_helper_rsync_lvlhsh_proto;
    lhq.pool = rsync_param.watch_pool;

    return njt_lvlhsh_delete(&rsync_param.wfd_to_watchinfo, &lhq);
}

static njt_int_t njt_helper_rsync_add_watch_item_to_lvlhash(njt_int_t watch_fd,
        rsync_inotify_file *watch_info){
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[50];
    u_char                                  *end;
    
    end = njt_snprintf(buff, 50, "%d", watch_fd);
    lhq.key.data = buff;
    lhq.key.len = end - buff;

    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_helper_rsync_lvlhsh_proto;
    lhq.pool = rsync_param.watch_pool;
    lhq.value = watch_info;

    return njt_lvlhsh_insert(&rsync_param.wfd_to_watchinfo, &lhq);
}



njt_int_t njt_helper_rsync_watch_identifier_exist(njt_str_t identifier,
            rsync_inotify_file **watch_info){
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[1024];
    u_char                                  *end;
    
    end = njt_snprintf(buff, 1024, "%V", &identifier);
    lhq.key.data = buff;
    lhq.key.len = end - buff;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_helper_rsync_lvlhsh_proto;
    lhq.pool = rsync_param.watch_pool;

    if(NJT_OK == njt_lvlhsh_find(&rsync_param.identifier_to_watchinfo, &lhq)){
        *watch_info = lhq.value;
        return NJT_OK;
    }

    return NJT_ERROR;
}


njt_int_t njt_helper_rsync_del_watch_identifier_from_lvlhash(njt_str_t identifier){
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[1024];
    u_char                                  *end;
    
    end = njt_snprintf(buff, 1024, "%V", &identifier);
    lhq.key.data = buff;
    lhq.key.len = end - buff;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_helper_rsync_lvlhsh_proto;
    lhq.pool = rsync_param.watch_pool;

    return njt_lvlhsh_delete(&rsync_param.identifier_to_watchinfo, &lhq);
}

njt_int_t njt_helper_rsync_add_watch_identifier_to_lvlhash(njt_str_t identifier,
        rsync_inotify_file *watch_info){
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[50];
    u_char                                  *end;
    
    end = njt_snprintf(buff, 1024, "%V", &identifier);
    lhq.key.data = buff;
    lhq.key.len = end - buff;

    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_helper_rsync_lvlhsh_proto;
    lhq.pool = rsync_param.watch_pool;
    lhq.value = watch_info;

    return njt_lvlhsh_insert(&rsync_param.identifier_to_watchinfo, &lhq);
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
    rsync_param.cycle = cycle;

    rsync_param.watch_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, cycle->log);
    if (rsync_param.watch_pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                " rsync create dynamic pool error");

        return NJT_ERROR;
    }
    njt_sub_pool(cycle->pool, rsync_param.watch_pool);

    njt_lvlhsh_init(&rsync_param.wfd_to_watchinfo);
    njt_lvlhsh_init(&rsync_param.identifier_to_watchinfo);

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
    // if (rsync_param.watch_dirs != NULL) {
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
