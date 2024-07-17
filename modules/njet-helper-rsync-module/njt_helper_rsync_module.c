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
#include "openrsync/extern.h"

extern njt_module_t  njt_gossip_module;
extern sig_atomic_t  njt_reconfigure;

#define NJT_KEEP_MASTER_CYCLE   1

#define NJT_HELPER_CMD_NO       0
#define NJT_HELPER_CMD_STOP     1
#define NJT_HELPER_CMD_RESTART  2

#define NJT_HELPER_VER          1

#define NJT_HELPER_RSYNC_FILE_TOPIC     "/dyn/fileupload"
#define NJT_HELPER_RSYNC_NODEINFO_TOPIC "/gossip/nodeinfo"
#define NJT_HELPER_RSYNC_TIMER_CLIENT_RETRY 1

typedef unsigned int (*helper_check_cmd_fp)(void *ctx);


typedef struct {
    njt_str_t   conf_fn;
    njt_str_t   conf_fullfn;
    helper_check_cmd_fp check_cmd_fp;
    void *ctx;
    void *cycle;
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
    char         *mqtt_conf_fn; // mqtt cong file, for subscribe
    char         *mqtt_client_id; 
    njt_array_t  *watch_files;
    char         *log_file;
} rsync_param;


static void njt_helper_rsync_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx);
static void njt_helper_rsync_loop_mqtt(njt_event_t *ev);

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


void
njt_helper_rsync_client_start(njt_array_t *files, int retry)
{ 
    size_t       argc, i, j, host_len; // k,
    char       **argv, *host_addr;
    njt_str_t   *args;
    njt_pid_t    pid;

    pid = fork();
    if (pid < 0) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "fork failed in njt_helper_rsync start");
        return;
    }

    if (pid > 0) {
        return; // parent
    }

    for (i = 0; i <= (size_t)retry; i++) {
        if (rsync_status->is_master) {
            break;
        }

        if (files == NULL) {
            // ./openrsync -t -r remote_ip:port/data/ ./data
            argc = 6;
            if ((argv = calloc(argc, sizeof(char *))) == NULL) {
                njt_log_error(NJT_LOG_ERR, sync_log, 0, "calloc failed in njt_helper_rsync start");
                return;
            }
            argv[0] = "./openrsync"; // nouse now
            argv[1] = "-t";
            argv[2] = "-v";
            argv[3] = "-v";
            argv[4] = njt_helper_rsync_get_host_addr();
            if (argv[3] == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "no master ip specified");
                break;
            }
            argv[5] = "./data/";

        } else {
            // gentrate argc argv for sync specify files
            argc = files->nelts + 4;
            if ((argv = calloc(argc, sizeof(char *))) == NULL) {
                njt_log_error(NJT_LOG_ERR, sync_log, 0, "calloc failed in njt_helper_rsync start");
                break;
            }

            argv[0] = "./openrsync"; // nouse now
            argv[1] = "-t";
            if (retry == 1) {
                argv[2] = "-v"; // from timer handler, 
            } else {
                argv[2] = "-vv"; // from msg handler
            }
            host_addr = njt_helper_rsync_get_host_addr(); // host_addr :    ip:port/data/
            if (host_addr == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "master_ip and port is null, return");
                break;
            } 
            host_len = strlen(host_addr);
            args = files->elts;
            argv[3] = malloc(host_len + args[0].len + 1);
            memcpy(argv[3], host_addr, (size_t)host_len);
            memcpy(argv[3]+host_len, args[0].data, args[0].len);
            argv[3][host_len + args[0].len] = 0;

            for (j = 1 ; j < files->nelts; j++) {
                argv[3+j] = calloc(7+args[j].len+1, sizeof(char));
                memcpy(argv[3+j], ":data/", 6);
                memcpy(argv[3+j]+6, (char *)args[j].data, args[j].len);
                argv[3+j][args[j].len+6] = 0;
            }
            argv[argc - 1] = "./data";

            if (argc == 5 && retry > 1) {
                njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "%s %s %s %s %s", argv[0], argv[1], argv[2], argv[3], argv[4]);
            }
        }

        int rc = njt_start_rsync(argc, argv); // 0 success, 1 failed in client, 2 failed in connection

        if ( rc == 0) {
            break; // rsync success
        }

        njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "njt_helper_rsync client retry %d times", i);
        sleep((i+1 > 10) ? 10 : i+1);
        // if (rc == 2 && retry > 1) { // rc = 2  rsync_connection failed, will try endlessly, rc == 1, receiver failed, try at most maxretry times
            // i--;
        // }
        if (files != NULL) {
            // free argv generated from files
            for (i = 0; i < files->nelts; i++){
                free(argv[3+i]);
            }
        }
    }

    if (retry == NJT_HELPER_RSYNC_TIMER_CLIENT_RETRY) {
        rsync_status->watch_client_busy = 0;// only one process can reach here
    }

    if (files == NULL) {
        rsync_status->full_sync_busy = 0; // only one process can reach here
    }
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
        return; // master do nothing
    }

    // hard coded sync dir to '/data/'
    new_host.len = strlen(mip) + strlen(port) + strlen("/data/") + 1 + 1;
    new_host.data = njt_pcalloc(njt_cycle->pool, new_host.len);
    if (new_host.data == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "parsing sync port failed, msg '%s'", msg);
        return;
    }
    njt_sprintf(new_host.data, "%s:%d/data/", mip, rsync_status->port);

    njt_shmtx_lock(&njt_helper_rsync_shpool->mutex);
    njt_memcpy(rsync_status->master_url, new_host.data, new_host.len);
    njt_shmtx_unlock(&njt_helper_rsync_shpool->mutex);
    njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "master node info: %s", rsync_status->master_url);
    njt_pfree(njt_cycle->pool, new_host.data);

    if (!rsync_status->is_master) {
        if (rsync_status->full_sync_busy) {
            rsync_status->master_changed = 1;
        } else {
            rsync_status->full_sync_busy = 1;
            sleep(1); // leave enough time for master node rsync daemon to start
            njt_helper_rsync_client_start(NULL, rsync_param.client_max_retry);
        }
    }

    return;

failed:
    return;
}


void
njt_helper_rsync_file_change_handler(const char *msg, size_t msg_len)
{
    // example msg  {"filename":"d6d567b0ad5f124e6d592e1fdee3e2eb.dat"}
    njt_pool_t    *dyn_pool;
    njt_array_t   *files;
    size_t         n_files = 1, f_len;
    njt_str_t     *file;
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
    f_len = strlen(fname);
    // printf("filename: %s\n", fname);

    dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (dyn_pool == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "rsync helper failed to allocate dyn pool");
        return;
    }

    // parse msg to array of file
    files = njt_array_create(dyn_pool, n_files, sizeof(njt_str_t));
    if (files == NULL) {
        njt_log_error(NJT_LOG_ERR, sync_log, 0, "rsync helper failed to create array");
        return;
    }

    file = njt_array_push(files);
    file->data = njt_pcalloc(dyn_pool, f_len + 1);
    njt_memcpy(file->data, fname, f_len);
    file->len = f_len + 1;
    
    // for more than one files, file_path is ':data/{file_name}', which is handled in func below
    njt_log_error(NJT_LOG_ERR, sync_log, 0, "rsync helper start client");
    njt_helper_rsync_client_start(files, rsync_param.client_max_retry);
    json_decref(root);
    njt_destroy_pool(dyn_pool);
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
    const char *name = "njet rsync daemon process";

    pid = fork();
    if (pid == 0) {
        if (prctl(PR_SET_NAME, (unsigned long) name) < 0) { // seem doesn't work
            njt_log_error(NJT_LOG_CRIT, sync_log, 0, "failed to prctl()");
        }

        // ./openrsync -t -r -vvvv --sender --server --exclude data/data.mdb --exclude data/lock.mdb --exclude data/mosquitto.db --exclude ".*" . ./data/
        argc = 20;
        if ((argv = calloc(argc, sizeof(char *))) == NULL) {
            njt_log_error(NJT_LOG_ERR, sync_log ,0,  "alloc error");
            exit(1);
        }

        char p[6];
        njt_memzero(p, 6);
        sprintf(p, "%d", port);

        argv[0] = "./openrsync"; // no use now
        argv[1] = "-r";
        argv[2] = "-t";
        argv[3] = "-v";
        argv[4] = "--server";
        argv[5] = "--sender";
        argv[6] = "--exclude";
        argv[7] = "data.mdb";
        argv[8] = "--exclude";
        argv[9] = "lock.mdb";
        argv[10] = "--exclude";
        argv[11] = "mosquitto.db";
        argv[12] = "--exclude";
        argv[13] = ".*"; // for hidden files
        argv[14] = "--address";
        argv[15] = strdup(bind_address);
        argv[16] = "--port";
        argv[17] = p;
        argv[18] = ".";
        argv[19] = "./data/";

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


njt_int_t
njt_helper_rsync_refresh_set_timer(njt_event_handler_pt h)
{
    njt_event_t *ev;
    njt_msec_t interval;

    ev = njt_pcalloc(njt_cycle->pool, sizeof(njt_event_t));
    if (ev == NULL) {
        njt_log_error(NJT_LOG_CRIT, sync_log, 0, "failed to allocate refresh event");
        exit(2);
    }
    ev->log = njt_cycle->log;
    ev->handler = h;
    ev->cancelable = 1;
    ev->data = NULL;
    interval = rsync_param.refresh_interval * 1000;
    njt_add_timer(ev, interval);

    return NJT_OK;
}

void
njt_helper_rsync_refresh_timer_handler(njt_event_t *ev)
{
    njt_msec_t interval;
    static njt_uint_t count;
    static njt_uint_t next_count = 100;
    
    if (rsync_status->is_master == 0 && rsync_param.watch_files != NULL) {
        if ((rsync_param.watch_files->nelts >= 10 || rsync_status->master_changed) && !rsync_status->full_sync_busy) {
            rsync_status->full_sync_busy = 1;
            njt_helper_rsync_client_start(NULL, rsync_param.client_max_retry);
            count++;
            rsync_status->master_changed = 0;
        } else {
            if (!rsync_status->watch_client_busy) {
                rsync_status->watch_client_busy = 1;
                njt_helper_rsync_client_start(rsync_param.watch_files, NJT_HELPER_RSYNC_TIMER_CLIENT_RETRY);
                count++;
            }
        }
    }

    if (count >= next_count) {
        njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "rsync helper refresh timer execute %l times", count);
        next_count += 100;
    }

    interval = rsync_param.refresh_interval * 1000;
    if (ev->timer_set) {
        njt_del_timer(ev);
    }
    njt_add_timer(ev, interval);
}

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


njt_int_t
njt_helper_rsync_parse_json(njt_cycle_t *cycle, char *conf_fn) {
    char *s;
    json_t *json;
    json_error_t error;
    json_t *cid, *mqtt_conf_fn, *max_retry, *interval, *files, *file, *log; 
    size_t  idx;
    njt_str_t *pos;
    struct rsync_param *param;

    param = &rsync_param;

    char *prefix;
    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    memcpy(prefix, cycle->prefix.data, cycle->prefix.len);
    prefix[cycle->prefix.len] = '\0';

    json = json_load_file(conf_fn, 0, &error);
    if (json == NULL) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "json == NULL, %s, use default configuration", conf_fn);
    }

    log = json_object_get(json, "log_file");
    if (log == NULL) {
        param->log_file = "logs/rsync.log";
    } else {
        param->log_file = strdup(json_string_value(log));
    }

    mqtt_conf_fn = json_object_get(json, "mqtt_conf");
    if (mqtt_conf_fn == NULL) {
        param->mqtt_conf_fn = concatenate_string(prefix, "conf/iot-ctrl.conf");
    } else {
        param->mqtt_conf_fn = concatenate_string(prefix, json_string_value(mqtt_conf_fn));
    }

    cid = json_object_get(json, "mqtt_client_id");
    if (cid == NULL) {
        param->mqtt_client_id = "rsync_mqtt_client";
    } else {
        param->mqtt_client_id = strdup(json_string_value(cid));
    }

    interval = json_object_get(json, "refresh_interval");
    if (interval == NULL) {
        param->refresh_interval = 10;
    } else {
        param->refresh_interval = (njt_int_t)json_integer_value(interval);
        param->refresh_interval = njt_max(5, param->refresh_interval);
    }

    max_retry = json_object_get(json, "client_max_retry");
    if (max_retry == NULL) {
        param->client_max_retry = 3;
    } else {
        param->client_max_retry = (njt_int_t)json_integer_value(max_retry);
        param->client_max_retry = njt_max(3, param->client_max_retry);
    }

    files = json_object_get(json, "watch_files");
    if (files == NULL || json_array_size(files) == 0) {
        param->watch_files = NULL;
    } else {
        njt_log_debug(NJT_LOG_NOTICE, cycle->log, 0, "parse rsync conf file watch list size '%ld' ", json_array_size(files));
        rsync_param.watch_files = njt_array_create(cycle->pool, json_array_size(files), sizeof(njt_str_t));
        json_array_foreach(files, idx, file) {
            pos = njt_array_push(rsync_param.watch_files);
            s = strdup(json_string_value(file));
            pos->data = (u_char*)s;
            pos->len = strlen(s);
        } 
    }

    njt_log_debug(NJT_LOG_NOTICE, cycle->log, 0, "parse rsync conf file '%s' successfully", conf_fn);

    njt_free(prefix);
    json_decref(json);
    return NJT_OK;
}


static njt_int_t njt_helper_rsync_init_mqtt_process (njt_cycle_t *cycle)
{
    char *prefix;
    int ret;

    char *localcfg = rsync_param.mqtt_conf_fn;
    char *client_id = rsync_param.mqtt_client_id;
    char *log = rsync_param.log_file;

    njt_cycle = cycle;

    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    njt_memcpy(prefix, cycle->prefix.data, cycle->prefix.len);
    
    prefix[cycle->prefix.len] = '\0';

    rsync_mqtt_ctx = njet_iot_client_init(prefix, localcfg, NULL, rsync_msg_callback, client_id, log, cycle);
    njt_free(prefix);
    
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

    njt_helper_rsync_parse_json(cycle, conf_fn);
    njt_helper_rsync_init_log(cycle);
    njt_helper_rsync_shm_init(cycle);

    njt_memzero(bind_address, 16);
    sprintf(bind_address, "%d.%d.%d.%d", gscf->node_info.ip[0],
            gscf->node_info.ip[1], gscf->node_info.ip[2], gscf->node_info.ip[3]);
    rsync_pid = njt_helper_rsync_daemon_start(cycle, bind_address, gscf->node_info.sync_port);
    
    njt_log_error(NJT_LOG_NOTICE, sync_log, 0, "bind_addrss: %s, port: %d",
                    bind_address, gscf->node_info.sync_port);
    
    if (rsync_pid == NJT_INVALID_PID) {
        return NJT_INVALID_PID;
    }

    sleep(1); // for mqtt server ready
    njt_helper_rsync_init_mqtt_process(cycle);
    if (rsync_param.watch_files != NULL) {
        njt_helper_rsync_refresh_set_timer(njt_helper_rsync_refresh_timer_handler);
    }

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

            rsync_daemon_pid = njt_helper_rsync_start_process(cycle, (char *)cycle->prefix.data, (char *)param.conf_fullfn.data);
            // printf("rsync_daemon_pid %d \n", rsync_daemon_pid);
            // printf("full fn  %s \n", param.conf_fullfn.data);
            if (rsync_daemon_pid == NJT_INVALID_PID) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper rsync start/reconfiguring failed, unable to start rsync daemon, possible reasons (no gossip conf or port confliction)");
                exit(2);
            } else {
                njt_reconfigure = 0;
            }
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
