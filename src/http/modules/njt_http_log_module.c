
// /*
//  * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
//  *


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include "njt_http_dyn_module.h"

#if (NJT_ZLIB)
#include <zlib.h>
#endif



#if (NJT_HTTP_DYN_LOG)
#include "njt_str_util.h"
#endif

typedef struct njt_http_log_op_s  njt_http_log_op_t;

typedef u_char *(*njt_http_log_op_run_pt) (njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);

typedef size_t (*njt_http_log_op_getlen_pt) (njt_http_request_t *r,
    uintptr_t data);


struct njt_http_log_op_s {
    size_t                      len;
    njt_http_log_op_getlen_pt   getlen;
    njt_http_log_op_run_pt      run;
    uintptr_t                   data;
};

//
//typedef struct {
//    njt_str_t                   name;
//    njt_array_t                *flushes;
//    njt_array_t                *ops;        /* array of njt_http_log_op_t */
//#if (NJT_HTTP_DYN_LOG)
//    njt_int_t                   ref_count; //引用计数
//    njt_pool_t                  *pool;     //
//#endif
//
//} njt_http_log_fmt_t;

#if (NJT_HTTP_DYN_LOG)
typedef struct {
    njt_queue_t queue;
    njt_int_t  ref_count; //引用计数
    njt_open_file_t file;
}njt_http_dyn_log_file_t;

#endif

//typedef struct {
//    njt_array_t                 formats;    /* array of njt_http_log_fmt_t */
//    njt_uint_t                  combined_used; /* unsigned  combined_used:1 */
//#if (NJT_HTTP_DYN_LOG)
//    njt_queue_t                 file_queue; /* 打开文件句柄列表 */
//    njt_pool_t                  *pool;
//#endif
//} njt_http_log_main_conf_t;


typedef struct {
    u_char                     *start;
    u_char                     *pos;
    u_char                     *last;

    njt_event_t                *event;
    njt_msec_t                  flush;
    njt_int_t                   gzip;
} njt_http_log_buf_t;


//typedef struct {
//    njt_array_t                *lengths;
//    njt_array_t                *values;
//} njt_http_log_script_t;


//typedef struct {
//    njt_open_file_t            *file;
//    njt_http_log_script_t      *script;
//    time_t                      disk_full_time;
//    time_t                      error_log_time;
//    njt_syslog_peer_t          *syslog_peer;
//    njt_http_log_fmt_t         *format;
//    njt_http_complex_value_t   *filter;
//} njt_http_log_t;

// 动态模块提取至njt_http_dyn_module.h by chengxu
//typedef struct {
//    njt_array_t                *logs;       /* array of njt_http_log_t */
//
//    njt_open_file_cache_t      *open_file_cache;
//    time_t                      open_file_cache_valid;
//    njt_uint_t                  open_file_cache_min_uses;
//
//    njt_uint_t                  off;        /* unsigned  off:1 */
//} njt_http_log_loc_conf_t;


typedef struct {
    njt_str_t                   name;
    size_t                      len;
    njt_http_log_op_run_pt      run;
} njt_http_log_var_t;


#define NJT_HTTP_LOG_ESCAPE_DEFAULT  0
#define NJT_HTTP_LOG_ESCAPE_JSON     1
#define NJT_HTTP_LOG_ESCAPE_NONE     2


static void njt_http_log_write(njt_http_request_t *r, njt_http_log_t *log,
    u_char *buf, size_t len);
static ssize_t njt_http_log_script_write(njt_http_request_t *r,
    njt_http_log_script_t *script, u_char **name, u_char *buf, size_t len);

#if (NJT_ZLIB)
static ssize_t njt_http_log_gzip(njt_fd_t fd, u_char *buf, size_t len,
    njt_int_t level, njt_log_t *log);

static void *njt_http_log_gzip_alloc(void *opaque, u_int items, u_int size);
static void njt_http_log_gzip_free(void *opaque, void *address);
#endif

static void njt_http_log_flush(njt_open_file_t *file, njt_log_t *log);
static void njt_http_log_flush_handler(njt_event_t *ev);

static u_char *njt_http_log_pipe(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);
static u_char *njt_http_log_time(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);
static u_char *njt_http_log_iso8601(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);
static u_char *njt_http_log_msec(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);
static u_char *njt_http_log_request_time(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);
static u_char *njt_http_log_status(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);
static u_char *njt_http_log_bytes_sent(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);
static u_char *njt_http_log_body_bytes_sent(njt_http_request_t *r,
    u_char *buf, njt_http_log_op_t *op);
static u_char *njt_http_log_request_length(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);

static njt_int_t njt_http_log_variable_compile(njt_conf_t *cf,
    njt_http_log_op_t *op, njt_str_t *value, njt_uint_t escape);
static size_t njt_http_log_variable_getlen(njt_http_request_t *r,
    uintptr_t data);
static u_char *njt_http_log_variable(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);
static uintptr_t njt_http_log_escape(u_char *dst, u_char *src, size_t size);
static size_t njt_http_log_json_variable_getlen(njt_http_request_t *r,
    uintptr_t data);
static u_char *njt_http_log_json_variable(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op);
static size_t njt_http_log_unescaped_variable_getlen(njt_http_request_t *r,
    uintptr_t data);
static u_char *njt_http_log_unescaped_variable(njt_http_request_t *r,
    u_char *buf, njt_http_log_op_t *op);


static void *njt_http_log_create_main_conf(njt_conf_t *cf);
static void *njt_http_log_create_loc_conf(njt_conf_t *cf);
static char *njt_http_log_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_log_set_log(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_log_set_format(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_log_compile_format(njt_conf_t *cf,
    njt_array_t *flushes, njt_array_t *ops, njt_array_t *args, njt_uint_t s);
static char *njt_http_log_open_file_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_log_init(njt_conf_t *cf);


static njt_command_t  njt_http_log_commands[] = {

    { njt_string("log_format"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_2MORE,
      njt_http_log_set_format,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("access_log"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_HTTP_LMT_CONF|NJT_CONF_1MORE,
      njt_http_log_set_log,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("open_log_file_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1234,
      njt_http_log_open_file_cache,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_log_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_log_init,                     /* postconfiguration */

    njt_http_log_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_log_create_loc_conf,          /* create location configuration */
    njt_http_log_merge_loc_conf            /* merge location configuration */
};


njt_module_t  njt_http_log_module = {
    NJT_MODULE_V1,
    &njt_http_log_module_ctx,              /* module context */
    njt_http_log_commands,                 /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_str_t  njt_http_access_log = njt_string(NJT_HTTP_LOG_PATH);

static njt_str_t njt_http_escape_default = njt_string("default");
static njt_str_t  njt_http_combined_fmt =
    njt_string("$remote_addr - $remote_user [$time_local] "
               "\"$request\" $status $body_bytes_sent "
               "\"$http_referer\" \"$http_user_agent\"");


static njt_http_log_var_t  njt_http_log_vars[] = {
    { njt_string("pipe"), 1, njt_http_log_pipe },
    { njt_string("time_local"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
                          njt_http_log_time },
    { njt_string("time_iso8601"), sizeof("1970-09-28T12:00:00+06:00") - 1,
                          njt_http_log_iso8601 },
    { njt_string("msec"), NJT_TIME_T_LEN + 4, njt_http_log_msec },
    { njt_string("request_time"), NJT_TIME_T_LEN + 4,
                          njt_http_log_request_time },
    { njt_string("status"), NJT_INT_T_LEN, njt_http_log_status },
    { njt_string("bytes_sent"), NJT_OFF_T_LEN, njt_http_log_bytes_sent },
    { njt_string("body_bytes_sent"), NJT_OFF_T_LEN,
                          njt_http_log_body_bytes_sent },
    { njt_string("request_length"), NJT_SIZE_T_LEN,
                          njt_http_log_request_length },

    { njt_null_string, 0, NULL }
};


static njt_int_t
njt_http_log_handler(njt_http_request_t *r)
{
    u_char                   *line, *p;
    size_t                    len, size;
    ssize_t                   n;
    njt_str_t                 val;
    njt_uint_t                i, l;
    njt_http_log_t           *log;
    njt_http_log_op_t        *op;
    njt_http_log_buf_t       *buffer;
    njt_http_log_loc_conf_t  *lcf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log handler");

    lcf = njt_http_get_module_loc_conf(r, njt_http_log_module);

    if (lcf->off) {
        return NJT_OK;
    }

    log = lcf->logs->elts;
    for (l = 0; l < lcf->logs->nelts; l++) {

        if (log[l].filter) {
            if (njt_http_complex_value(r, log[l].filter, &val) != NJT_OK) {
                return NJT_ERROR;
            }

            if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
                continue;
            }
        }

        if (njt_time() == log[l].disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            continue;
        }

        njt_http_script_flush_no_cacheable_variables(r, log[l].format->flushes);

        len = 0;
        op = log[l].format->ops->elts;
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(r, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        if (log[l].syslog_peer) {

            /* length of syslog's PRI and HEADER message parts */
            len += sizeof("<255>Jan 01 00:00:00 ") - 1
                   + njt_cycle->hostname.len + 1
                   + log[l].syslog_peer->tag.len + 2;

            goto alloc_line;
        }

        len += NJT_LINEFEED_SIZE;

        buffer = log[l].file ? log[l].file->data : NULL;

        if (buffer) {

            if (len > (size_t) (buffer->last - buffer->pos)) {

                njt_http_log_write(r, &log[l], buffer->start,
                                   buffer->pos - buffer->start);

                buffer->pos = buffer->start;
            }

            if (len <= (size_t) (buffer->last - buffer->pos)) {

                p = buffer->pos;

                if (buffer->event && p == buffer->start) {
                    njt_add_timer(buffer->event, buffer->flush);
                }

                for (i = 0; i < log[l].format->ops->nelts; i++) {
                    p = op[i].run(r, p, &op[i]);
                }

                njt_linefeed(p);

                buffer->pos = p;

                continue;
            }

            if (buffer->event && buffer->event->timer_set) {
                njt_del_timer(buffer->event);
            }
        }

    alloc_line:

        line = njt_pnalloc(r->pool, len);
        if (line == NULL) {
            return NJT_ERROR;
        }

        p = line;

        if (log[l].syslog_peer) {
            p = njt_syslog_add_header(log[l].syslog_peer, line);
        }

        for (i = 0; i < log[l].format->ops->nelts; i++) {
            p = op[i].run(r, p, &op[i]);
        }

        if (log[l].syslog_peer) {

            size = p - line;

            n = njt_syslog_send(log[l].syslog_peer, line, size);

            if (n < 0) {
                njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                              "send() to syslog failed");

            } else if ((size_t) n != size) {
                njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                              "send() to syslog has written only %z of %uz",
                              n, size);
            }

            continue;
        }

        njt_linefeed(p);

        njt_http_log_write(r, &log[l], line, p - line);
    }

    return NJT_OK;
}


static void
njt_http_log_write(njt_http_request_t *r, njt_http_log_t *log, u_char *buf,
    size_t len)
{
    u_char              *name;
    time_t               now;
    ssize_t              n;
    njt_err_t            err;
    njt_str_t              def = njt_string("null file");
#if (NJT_ZLIB)
    njt_http_log_buf_t  *buffer;
#endif

    if (log->script == NULL) {
        if(log->file == NULL) {
		return;
        }
	name = log->file->name.data;

#if (NJT_ZLIB)
        buffer = log->file->data;

        if (buffer && buffer->gzip) {
            n = njt_http_log_gzip(log->file->fd, buf, len, buffer->gzip,
                                  r->connection->log);
        } else {
            n = njt_write_fd(log->file->fd, buf, len);
        }
#else
        n = njt_write_fd(log->file->fd, buf, len);
#endif

    } else {
        name = NULL;
        n = njt_http_log_script_write(r, log->script, &name, buf, len);
    }

    if (n == (ssize_t) len) {
        return;
    }

    now = njt_time();

    if (n == -1) {
        err = njt_errno;

        if (err == NJT_ENOSPC) {
            log->disk_full_time = now;
        }

        if (now - log->error_log_time > 59) {
	    name = (name != NULL ?name:def.data);
            njt_log_error(NJT_LOG_ALERT, r->connection->log, err,
                          njt_write_fd_n " to \"%s\" failed", name);

            log->error_log_time = now;
        }

        return;
    }

    if (now - log->error_log_time > 59) {
	name = (name != NULL ?name:def.data);
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      njt_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      name, n, len);

        log->error_log_time = now;
    }
}


static ssize_t
njt_http_log_script_write(njt_http_request_t *r, njt_http_log_script_t *script,
    u_char **name, u_char *buf, size_t len)
{
    size_t                     root;
    ssize_t                    n;
    njt_str_t                  log, path;
    njt_open_file_info_t       of;
    njt_http_log_loc_conf_t   *llcf;
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (!r->root_tested) {

        /* test root directory existence */

        if (njt_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            /* simulate successful logging */
            return len;
        }

        path.data[root] = '\0';

        njt_memzero(&of, sizeof(njt_open_file_info_t));

        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_dir = 1;
        of.test_only = 1;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (njt_http_set_disable_symlinks(r, clcf, &path, &of) != NJT_OK) {
            /* simulate successful logging */
            return len;
        }

        if (njt_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NJT_OK)
        {
            if (of.err == 0) {
                /* simulate successful logging */
                return len;
            }

            njt_log_error(NJT_LOG_ERR, r->connection->log, of.err,
                          "testing \"%s\" existence failed", path.data);

            /* simulate successful logging */
            return len;
        }

        if (!of.is_dir) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, NJT_ENOTDIR,
                          "testing \"%s\" existence failed", path.data);

            /* simulate successful logging */
            return len;
        }
    }

    if (njt_http_script_run(r, &log, script->lengths->elts, 1,
                            script->values->elts)
        == NULL)
    {
        /* simulate successful logging */
        return len;
    }

    log.data[log.len - 1] = '\0';
    *name = log.data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log \"%s\"", log.data);

    llcf = njt_http_get_module_loc_conf(r, njt_http_log_module);

    njt_memzero(&of, sizeof(njt_open_file_info_t));

    of.log = 1;
    of.valid = llcf->open_file_cache_valid;
    of.min_uses = llcf->open_file_cache_min_uses;
    of.directio = NJT_OPEN_FILE_DIRECTIO_OFF;

    if (njt_http_set_disable_symlinks(r, clcf, &log, &of) != NJT_OK) {
        /* simulate successful logging */
        return len;
    }

    if (njt_open_cached_file(llcf->open_file_cache, &log, &of, r->pool)
        != NJT_OK)
    {
        if (of.err == 0) {
            /* simulate successful logging */
            return len;
        }

        njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                      "%s \"%s\" failed", of.failed, log.data);
        /* simulate successful logging */
        return len;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log #%d", of.fd);
    n = njt_write_fd(of.fd, buf, len);

    return n;
}


#if (NJT_ZLIB)

static ssize_t
njt_http_log_gzip(njt_fd_t fd, u_char *buf, size_t len, njt_int_t level,
    njt_log_t *log)
{
    int          rc, wbits, memlevel;
    u_char      *out;
    size_t       size;
    ssize_t      n;
    z_stream     zstream;
    njt_err_t    err;
    njt_pool_t  *pool;

    wbits = MAX_WBITS;
    memlevel = MAX_MEM_LEVEL - 1;

    while ((ssize_t) len < ((1 << (wbits - 1)) - 262)) {
        wbits--;
        memlevel--;
    }

    /*
     * This is a formula from deflateBound() for conservative upper bound of
     * compressed data plus 18 bytes of gzip wrapper.
     */

    size = len + ((len + 7) >> 3) + ((len + 63) >> 6) + 5 + 18;

    njt_memzero(&zstream, sizeof(z_stream));

    pool = njt_create_pool(256, log);
    if (pool == NULL) {
        /* simulate successful logging */
        return len;
    }

    pool->log = log;

    zstream.zalloc = njt_http_log_gzip_alloc;
    zstream.zfree = njt_http_log_gzip_free;
    zstream.opaque = pool;

    out = njt_pnalloc(pool, size);
    if (out == NULL) {
        goto done;
    }

    zstream.next_in = buf;
    zstream.avail_in = len;
    zstream.next_out = out;
    zstream.avail_out = size;

    rc = deflateInit2(&zstream, (int) level, Z_DEFLATED, wbits + 16, memlevel,
                      Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        njt_log_error(NJT_LOG_ALERT, log, 0, "deflateInit2() failed: %d", rc);
        goto done;
    }

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, log, 0,
                   "deflate in: ni:%p no:%p ai:%ud ao:%ud",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out);

    rc = deflate(&zstream, Z_FINISH);

    if (rc != Z_STREAM_END) {
        njt_log_error(NJT_LOG_ALERT, log, 0,
                      "deflate(Z_FINISH) failed: %d", rc);
        goto done;
    }

    njt_log_debug5(NJT_LOG_DEBUG_HTTP, log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out,
                   rc);

    size -= zstream.avail_out;

    rc = deflateEnd(&zstream);

    if (rc != Z_OK) {
        njt_log_error(NJT_LOG_ALERT, log, 0, "deflateEnd() failed: %d", rc);
        goto done;
    }

    n = njt_write_fd(fd, out, size);

    if (n != (ssize_t) size) {
        err = (n == -1) ? njt_errno : 0;

        njt_destroy_pool(pool);

        njt_set_errno(err);
        return -1;
    }

done:

    njt_destroy_pool(pool);

    /* simulate successful logging */
    return len;
}


static void *
njt_http_log_gzip_alloc(void *opaque, u_int items, u_int size)
{
    njt_pool_t *pool = opaque;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "gzip alloc: n:%ud s:%ud", items, size);

    return njt_palloc(pool, items * size);
}


static void
njt_http_log_gzip_free(void *opaque, void *address)
{
#if 0
    njt_pool_t *pool = opaque;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0, "gzip free: %p", address);
#endif
}

#endif


static void
njt_http_log_flush(njt_open_file_t *file, njt_log_t *log)
{
    size_t               len;
    ssize_t              n;
    njt_http_log_buf_t  *buffer;

    buffer = file->data;

    len = buffer->pos - buffer->start;

    if (len == 0) {
        return;
    }

#if (NJT_ZLIB)
    if (buffer->gzip) {
        n = njt_http_log_gzip(file->fd, buffer->start, len, buffer->gzip, log);
    } else {
        n = njt_write_fd(file->fd, buffer->start, len);
    }
#else
    n = njt_write_fd(file->fd, buffer->start, len);
#endif

    if (n == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      njt_write_fd_n " to \"%s\" failed",
                      file->name.data);

    } else if ((size_t) n != len) {
        njt_log_error(NJT_LOG_ALERT, log, 0,
                      njt_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      file->name.data, n, len);
    }

    buffer->pos = buffer->start;

    if (buffer->event && buffer->event->timer_set) {
        njt_del_timer(buffer->event);
    }
}


static void
njt_http_log_flush_handler(njt_event_t *ev)
{
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "http log buffer flush handler");

    njt_http_log_flush(ev->data, ev->log);
}


static u_char *
njt_http_log_copy_short(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op)
{
    size_t     len;
    uintptr_t  data;

    len = op->len;
    data = op->data;

    while (len--) {
        *buf++ = (u_char) (data & 0xff);
        data >>= 8;
    }

    return buf;
}


static u_char *
njt_http_log_copy_long(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op)
{
    return njt_cpymem(buf, (u_char *) op->data, op->len);
}


static u_char *
njt_http_log_pipe(njt_http_request_t *r, u_char *buf, njt_http_log_op_t *op)
{
    if (r->pipeline) {
        *buf = 'p';
    } else {
        *buf = '.';
    }

    return buf + 1;
}


static u_char *
njt_http_log_time(njt_http_request_t *r, u_char *buf, njt_http_log_op_t *op)
{
    return njt_cpymem(buf, njt_cached_http_log_time.data,
                      njt_cached_http_log_time.len);
}

static u_char *
njt_http_log_iso8601(njt_http_request_t *r, u_char *buf, njt_http_log_op_t *op)
{
    return njt_cpymem(buf, njt_cached_http_log_iso8601.data,
                      njt_cached_http_log_iso8601.len);
}

static u_char *
njt_http_log_msec(njt_http_request_t *r, u_char *buf, njt_http_log_op_t *op)
{
    njt_time_t  *tp;

    tp = njt_timeofday();

    return njt_sprintf(buf, "%T.%03M", tp->sec, tp->msec);
}


static u_char *
njt_http_log_request_time(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op)
{
    njt_time_t      *tp;
    njt_msec_int_t   ms;

    tp = njt_timeofday();

    ms = (njt_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = njt_max(ms, 0);

    return njt_sprintf(buf, "%T.%03M", (time_t) ms / 1000, ms % 1000);
}


static u_char *
njt_http_log_status(njt_http_request_t *r, u_char *buf, njt_http_log_op_t *op)
{
    njt_uint_t  status;

    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == NJT_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }

    return njt_sprintf(buf, "%03ui", status);
}


static u_char *
njt_http_log_bytes_sent(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op)
{
    return njt_sprintf(buf, "%O", r->connection->sent);
}


/*
 * although there is a real $body_bytes_sent variable,
 * this log operation code function is more optimized for logging
 */

static u_char *
njt_http_log_body_bytes_sent(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op)
{
    off_t  length;

    length = r->connection->sent - r->header_size;

    if (length > 0) {
        return njt_sprintf(buf, "%O", length);
    }

    *buf = '0';

    return buf + 1;
}


static u_char *
njt_http_log_request_length(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op)
{
    return njt_sprintf(buf, "%O", r->request_length);
}


static njt_int_t
njt_http_log_variable_compile(njt_conf_t *cf, njt_http_log_op_t *op,
    njt_str_t *value, njt_uint_t escape)
{
    njt_int_t  index;

    index = njt_http_get_variable_index(cf, value);
    if (index == NJT_ERROR) {
        return NJT_ERROR;
    }

    op->len = 0;

    switch (escape) {
    case NJT_HTTP_LOG_ESCAPE_JSON:
        op->getlen = njt_http_log_json_variable_getlen;
        op->run = njt_http_log_json_variable;
        break;

    case NJT_HTTP_LOG_ESCAPE_NONE:
        op->getlen = njt_http_log_unescaped_variable_getlen;
        op->run = njt_http_log_unescaped_variable;
        break;

    default: /* NJT_HTTP_LOG_ESCAPE_DEFAULT */
        op->getlen = njt_http_log_variable_getlen;
        op->run = njt_http_log_variable;
    }

    op->data = index;

    return NJT_OK;
}


static size_t
njt_http_log_variable_getlen(njt_http_request_t *r, uintptr_t data)
{
    uintptr_t                   len;
    njt_http_variable_value_t  *value;

    value = njt_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 1;
    }

    len = njt_http_log_escape(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len * 3;
}


static u_char *
njt_http_log_variable(njt_http_request_t *r, u_char *buf, njt_http_log_op_t *op)
{
    njt_http_variable_value_t  *value;

    value = njt_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        *buf = '-';
        return buf + 1;
    }

    if (value->escape == 0) {
        return njt_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) njt_http_log_escape(buf, value->data, value->len);
    }
}


static uintptr_t
njt_http_log_escape(u_char *dst, u_char *src, size_t size)
{
    njt_uint_t      n;
    static u_char   hex[] = "0123456789ABCDEF";

    static uint32_t   escape[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };


    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n = 0;

        while (size) {
            if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
                n++;
            }
            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
            *dst++ = '\\';
            *dst++ = 'x';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
        size--;
    }

    return (uintptr_t) dst;
}


static size_t
njt_http_log_json_variable_getlen(njt_http_request_t *r, uintptr_t data)
{
    uintptr_t                   len;
    njt_http_variable_value_t  *value;

    value = njt_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 0;
    }

    len = njt_escape_json(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len;
}


static u_char *
njt_http_log_json_variable(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op)
{
    njt_http_variable_value_t  *value;

    value = njt_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        return buf;
    }

    if (value->escape == 0) {
        return njt_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) njt_escape_json(buf, value->data, value->len);
    }
}


static size_t
njt_http_log_unescaped_variable_getlen(njt_http_request_t *r, uintptr_t data)
{
    njt_http_variable_value_t  *value;

    value = njt_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 0;
    }

    value->escape = 0;

    return value->len;
}


static u_char *
njt_http_log_unescaped_variable(njt_http_request_t *r, u_char *buf,
    njt_http_log_op_t *op)
{
    njt_http_variable_value_t  *value;

    value = njt_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        return buf;
    }

    return njt_cpymem(buf, value->data, value->len);
}


static void *
njt_http_log_create_main_conf(njt_conf_t *cf)
{
    njt_http_log_main_conf_t  *conf;

    njt_http_log_fmt_t  *fmt;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_log_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (NJT_HTTP_DYN_LOG)
    njt_queue_init(&conf->file_queue);
    conf->combined_used =1;
    njt_pool_t *new_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, cf->pool->log);
    if (new_pool == NULL) {
        return NULL;
    }
    njt_sub_pool(cf->cycle->pool ,new_pool);
    conf->pool = new_pool;
#endif

    // www: up to 16 formats
    if (njt_array_init(&conf->formats, cf->pool, 16, sizeof(njt_http_log_fmt_t))
        != NJT_OK)
    {
        return NULL;
    }

    fmt = njt_array_push(&conf->formats);
    if (fmt == NULL) {
        return NULL;
    }

    njt_str_set(&fmt->name, "combined");

    fmt->flushes = NULL;

    fmt->ops = njt_array_create(cf->pool, 16, sizeof(njt_http_log_op_t));
    if (fmt->ops == NULL) {
        return NULL;
    }

    return conf;
}


static void *
njt_http_log_create_loc_conf(njt_conf_t *cf)
{
    njt_http_log_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_log_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->open_file_cache = NJT_CONF_UNSET_PTR;

    return conf;
}


static char *
njt_http_log_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_log_loc_conf_t *prev = parent;
    njt_http_log_loc_conf_t *conf = child;

    njt_http_log_t            *log;
    njt_http_log_fmt_t        *fmt;
    njt_http_log_main_conf_t  *lmcf;

    if (conf->open_file_cache == NJT_CONF_UNSET_PTR) {

        conf->open_file_cache = prev->open_file_cache;
        conf->open_file_cache_valid = prev->open_file_cache_valid;
        conf->open_file_cache_min_uses = prev->open_file_cache_min_uses;

        if (conf->open_file_cache == NJT_CONF_UNSET_PTR) {
            conf->open_file_cache = NULL;
        }
    }

    if (conf->logs || conf->off) {
        return NJT_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    if (conf->logs || conf->off) {
        return NJT_CONF_OK;
    }

    conf->logs = njt_array_create(cf->pool, 2, sizeof(njt_http_log_t));
    if (conf->logs == NULL) {
        return NJT_CONF_ERROR;
    }

    log = njt_array_push(conf->logs);
    if (log == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(log, sizeof(njt_http_log_t));

    log->file = njt_conf_open_file(cf->cycle, &njt_http_access_log);
    if (log->file == NULL) {
        return NJT_CONF_ERROR;
    }
    log->path = njt_http_access_log;
    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_log_module);
    fmt = lmcf->formats.elts;

    /* the default "combined" format */
    log->format = &fmt[0];
    lmcf->combined_used = 1;

    return NJT_CONF_OK;
}


static char *
njt_http_log_set_log(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_log_loc_conf_t *llcf = conf;

    ssize_t                            size;
    njt_int_t                          gzip;
    njt_uint_t                         i, n;
    njt_msec_t                         flush;
    njt_str_t                         *value, name, s;
    njt_http_log_t                    *log;
    njt_syslog_peer_t                 *peer;
    njt_http_log_buf_t                *buffer;
    njt_http_log_fmt_t                *fmt;
    njt_http_log_main_conf_t          *lmcf;
    njt_http_script_compile_t          sc;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        llcf->off = 1;
        if (cf->args->nelts == 2) {
            return NJT_CONF_OK;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NJT_CONF_ERROR;
    }
    if (llcf->logs == NULL) {
        llcf->logs = njt_array_create(cf->pool, 2, sizeof(njt_http_log_t));
        if (llcf->logs == NULL) {
            return NJT_CONF_ERROR;
        }
    }
    llcf->dynamic = 0;
    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_log_module);

    log = njt_array_push(llcf->logs);
    if (log == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(log, sizeof(njt_http_log_t));
    njt_str_copy_pool(cf->pool,log->path,value[1],return NJT_CONF_ERROR);


    if (njt_strncmp(value[1].data, "syslog:", 7) == 0) {

        peer = njt_pcalloc(cf->pool, sizeof(njt_syslog_peer_t));
        if (peer == NULL) {
            return NJT_CONF_ERROR;
        }

        if (njt_syslog_process_conf(cf, peer) != NJT_CONF_OK) {
            return NJT_CONF_ERROR;
        }

        log->syslog_peer = peer;

        goto process_formats;
    }

    n = njt_http_script_variables_count(&value[1]);

    if (n == 0) {
        log->file = njt_conf_open_file(cf->cycle, &value[1]);
        if (log->file == NULL) {
            return NJT_CONF_ERROR;
        }

    } else {
        if (njt_conf_full_name(cf->cycle, &value[1], 0) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        log->script = njt_pcalloc(cf->pool, sizeof(njt_http_log_script_t));
        if (log->script == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_memzero(&sc, sizeof(njt_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &log->script->lengths;
        sc.values = &log->script->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

process_formats:

    if (cf->args->nelts >= 3) {
        name = value[2];

        if (njt_strcmp(name.data, "combined") == 0) {
            lmcf->combined_used = 1;
        }

    } else {
        njt_str_set(&name, "combined");
        lmcf->combined_used = 1;
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && njt_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->format = &fmt[i];
            break;
        }
    }

    if (log->format == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "unknown log format \"%V\"", &name);
        return NJT_CONF_ERROR;
    }

    size = 0;
    flush = 0;
    gzip = 0;

    for (i = 3; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "buffer=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            size = njt_parse_size(&s);

            if (size == NJT_ERROR || size == 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid buffer size \"%V\"", &s);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "flush=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            flush = njt_parse_time(&s, 0);

            if (flush == (njt_msec_t) NJT_ERROR || flush == 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid flush time \"%V\"", &s);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "gzip", 4) == 0
            && (value[i].len == 4 || value[i].data[4] == '='))
        {
#if (NJT_ZLIB)
            if (size == 0) {
                size = 64 * 1024;
            }

            if (value[i].len == 4) {
                gzip = Z_BEST_SPEED;
                continue;
            }

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            gzip = njt_atoi(s.data, s.len);

            if (gzip < 1 || gzip > 9) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid compression level \"%V\"", &s);
                return NJT_CONF_ERROR;
            }

            continue;

#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "njet was built without zlib support");
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strncmp(value[i].data, "if=", 3) == 0) {
            s.len = value[i].len - 3;
            s.data = value[i].data + 3;

            njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = njt_palloc(cf->pool,
                                           sizeof(njt_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NJT_CONF_ERROR;
            }

            if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

            log->filter = ccv.complex_value;

            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    if (flush && size == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "no buffer is defined for access_log \"%V\"",
                           &value[1]);
        return NJT_CONF_ERROR;
    }

    if (size) {

        if (log->script) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "buffered logs cannot have variables in name");
            return NJT_CONF_ERROR;
        }

        if (log->syslog_peer) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "logs to syslog cannot be buffered");
            return NJT_CONF_ERROR;
        }

        if (log->file->data) {
            buffer = log->file->data;

            if (buffer->last - buffer->start != size
                || buffer->flush != flush
                || buffer->gzip != gzip)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "access_log \"%V\" already defined "
                                   "with conflicting parameters",
                                   &value[1]);
                return NJT_CONF_ERROR;
            }

            return NJT_CONF_OK;
        }

        buffer = njt_pcalloc(cf->pool, sizeof(njt_http_log_buf_t));
        if (buffer == NULL) {
            return NJT_CONF_ERROR;
        }

        buffer->start = njt_pnalloc(cf->pool, size);
        if (buffer->start == NULL) {
            return NJT_CONF_ERROR;
        }

        buffer->pos = buffer->start;
        buffer->last = buffer->start + size;

        if (flush) {
            buffer->event = njt_pcalloc(cf->pool, sizeof(njt_event_t));
            if (buffer->event == NULL) {
                return NJT_CONF_ERROR;
            }

            buffer->event->data = log->file;
            buffer->event->handler = njt_http_log_flush_handler;
            buffer->event->log = &cf->cycle->new_log;
            buffer->event->cancelable = 1;

            buffer->flush = flush;
        }

        buffer->gzip = gzip;

        log->file->flush = njt_http_log_flush;
        log->file->data = buffer;
    }
    return NJT_CONF_OK;
}


static char *
njt_http_log_set_format(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_log_main_conf_t *lmcf = conf;

    njt_str_t           *value,last;
    njt_uint_t           i,start;
    njt_http_log_fmt_t  *fmt;

    value = cf->args->elts;

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len
            && njt_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "duplicate \"log_format\" name \"%V\"",
                               &value[1]);
            return NJT_CONF_ERROR;
        }
    }

    fmt = njt_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NJT_CONF_ERROR;
    }
    njt_memzero(fmt, sizeof(njt_http_log_fmt_t));
    fmt->dynamic = 0;
    fmt->name = value[1];
    start = 2;
    if (value[2].len > 7 && njt_strncmp(value[2].data, "escape=", 7) == 0) {
        last.data = value[2].data+7;
        last.len = value[2].len-7;
        njt_str_copy_pool(cf->pool,fmt->escape,last,return NJT_CONF_ERROR);
        ++start;
    }
    njt_str_null(&last) ;
    for(i = start ; i < cf->args->nelts; ++i ){
        njt_str_concat(cf->pool,fmt->format,last,value[i],return NJT_CONF_ERROR);
        last = fmt->format;
    }

    fmt->flushes = njt_array_create(cf->pool, 4, sizeof(njt_int_t));
    if (fmt->flushes == NULL) {
        return NJT_CONF_ERROR;
    }

    fmt->ops = njt_array_create(cf->pool, 16, sizeof(njt_http_log_op_t));
    if (fmt->ops == NULL) {
        return NJT_CONF_ERROR;
    }

    return njt_http_log_compile_format(cf, fmt->flushes, fmt->ops, cf->args, 2);
}


static char *
njt_http_log_compile_format(njt_conf_t *cf, njt_array_t *flushes,
    njt_array_t *ops, njt_array_t *args, njt_uint_t s)
{
    u_char              *data, *p, ch;
    size_t               i, len;
    njt_str_t           *value, var;
    njt_int_t           *flush;
    njt_uint_t           bracket, escape;
    njt_http_log_op_t   *op;
    njt_http_log_var_t  *v;

    escape = NJT_HTTP_LOG_ESCAPE_DEFAULT;
    value = args->elts;

    if (s < args->nelts && njt_strncmp(value[s].data, "escape=", 7) == 0) {
        data = value[s].data + 7;

        if (njt_strcmp(data, "json") == 0) {
            escape = NJT_HTTP_LOG_ESCAPE_JSON;

        } else if (njt_strcmp(data, "none") == 0) {
            escape = NJT_HTTP_LOG_ESCAPE_NONE;

        } else if (njt_strcmp(data, "default") != 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "unknown log format escaping \"%s\"", data);
            return NJT_CONF_ERROR;
        }

        s++;
    }

    for ( /* void */ ; s < args->nelts; s++) {

        i = 0;

        while (i < value[s].len) {

            op = njt_array_push(ops);
            if (op == NULL) {
                return NJT_CONF_ERROR;
            }

            data = &value[s].data[i];

            if (value[s].data[i] == '$') {

                if (++i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    bracket = 1;

                    if (++i == value[s].len) {
                        goto invalid;
                    }

                    var.data = &value[s].data[i];

                } else {
                    bracket = 0;
                    var.data = &value[s].data[i];
                }

                for (var.len = 0; i < value[s].len; i++, var.len++) {
                    ch = value[s].data[i];

                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;
                        break;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || ch == '_')
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return NJT_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                for (v = njt_http_log_vars; v->name.len; v++) {

                    if (v->name.len == var.len
                        && njt_strncmp(v->name.data, var.data, var.len) == 0)
                    {
                        op->len = v->len;
                        op->getlen = NULL;
                        op->run = v->run;
                        op->data = 0;

                        goto found;
                    }
                }

                if (njt_http_log_variable_compile(cf, op, &var, escape)
                    != NJT_OK)
                {
                    return NJT_CONF_ERROR;
                }

                if (flushes) {

                    flush = njt_array_push(flushes);
                    if (flush == NULL) {
                        return NJT_CONF_ERROR;
                    }

                    *flush = op->data; /* variable index */
                }

            found:

                continue;
            }

            i++;

            while (i < value[s].len && value[s].data[i] != '$') {
                i++;
            }

            len = &value[s].data[i] - data;

            if (len) {

                op->len = len;
                op->getlen = NULL;

                if (len <= sizeof(uintptr_t)) {
                    op->run = njt_http_log_copy_short;
                    op->data = 0;

                    while (len--) {
                        op->data <<= 8;
                        op->data |= data[len];
                    }

                } else {
                    op->run = njt_http_log_copy_long;

                    p = njt_pnalloc(cf->pool, len);
                    if (p == NULL) {
                        return NJT_CONF_ERROR;
                    }

                    njt_memcpy(p, data, len);
                    op->data = (uintptr_t) p;
                }
            }
        }
    }

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NJT_CONF_ERROR;
}


static char *
njt_http_log_open_file_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_log_loc_conf_t *llcf = conf;

    time_t       inactive, valid;
    njt_str_t   *value, s;
    njt_int_t    max, min_uses;
    njt_uint_t   i;

    if (llcf->open_file_cache != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 10;
    valid = 60;
    min_uses = 1;

    for (i = 1; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "max=", 4) == 0) {

            max = njt_atoi(value[i].data + 4, value[i].len - 4);
            if (max == NJT_ERROR) {
                goto failed;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = njt_parse_time(&s, 1);
            if (inactive == (time_t) NJT_ERROR) {
                goto failed;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "min_uses=", 9) == 0) {

            min_uses = njt_atoi(value[i].data + 9, value[i].len - 9);
            if (min_uses == NJT_ERROR) {
                goto failed;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "valid=", 6) == 0) {

            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            valid = njt_parse_time(&s, 1);
            if (valid == (time_t) NJT_ERROR) {
                goto failed;
            }

            continue;
        }

        if (njt_strcmp(value[i].data, "off") == 0) {

            llcf->open_file_cache = NULL;

            continue;
        }

    failed:

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid \"open_log_file_cache\" parameter \"%V\"",
                           &value[i]);
        return NJT_CONF_ERROR;
    }

    if (llcf->open_file_cache == NULL) {
        return NJT_CONF_OK;
    }

    if (max == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                        "\"open_log_file_cache\" must have \"max\" parameter");
        return NJT_CONF_ERROR;
    }

    llcf->open_file_cache = njt_open_file_cache_init(cf->pool, max, inactive);

    if (llcf->open_file_cache) {

        llcf->open_file_cache_valid = valid;
        llcf->open_file_cache_min_uses = min_uses;

        return NJT_CONF_OK;
    }

    return NJT_CONF_ERROR;
}


static njt_int_t
njt_http_log_init(njt_conf_t *cf)
{
    njt_str_t                  *value;
    njt_array_t                 a;
    njt_http_handler_pt        *h;
    njt_http_log_fmt_t         *fmt;
    njt_http_log_main_conf_t   *lmcf;
    njt_http_core_main_conf_t  *cmcf;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_log_module);

    if (lmcf->combined_used) {
        if (njt_array_init(&a, cf->pool, 1, sizeof(njt_str_t)) != NJT_OK) {
            return NJT_ERROR;
        }

        value = njt_array_push(&a);
        if (value == NULL) {
            return NJT_ERROR;
        }

        *value = njt_http_combined_fmt;
        fmt = lmcf->formats.elts;
        fmt->format = njt_http_combined_fmt;
        njt_str_copy_pool(cf->pool,fmt->escape, njt_http_escape_default,return NJT_ERROR);
        fmt->escape.len = njt_http_escape_default.len;
        fmt->dynamic = 0;
        if (njt_http_log_compile_format(cf, NULL, fmt->ops, &a, 0)
            != NJT_CONF_OK)
        {
            return NJT_ERROR;
        }
    }

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_log_handler;

    return NJT_OK;
}


#if (NJT_HTTP_DYN_LOG)


static void njt_http_log_dyn_unused_file(void *data){
    njt_http_dyn_log_file_t *file;
    njt_http_log_main_conf_t *lmcf;

    file = data;
    --file->ref_count;

    if(njt_cycle->conf_ctx == NULL){
        return;
    }
    lmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_log_module);
    if(lmcf == NULL){
        return;
    }
    if(file->ref_count == 0 ){
        if (njt_close_file(file->file.fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,njt_close_file_n " \"%V\" failed", &file->file.name);
        }
        njt_queue_remove(&file->queue);
        njt_pfree(lmcf->pool,file);
    }
}
static void njt_http_log_dyn_using_file(njt_pool_t *pool,njt_http_dyn_log_file_t *file){
    njt_pool_cleanup_t * cln;

    ++file->ref_count;
    cln = njt_pool_cleanup_add(pool,0);
    if( cln == NULL ){
        return;
    }
    cln->data = file;
    cln->handler = njt_http_log_dyn_unused_file;
}
// 未使用需检查文件引用计数，此处不会随lmcf.pool 自动释放
static njt_http_dyn_log_file_t * njt_http_log_dyn_open_file(njt_http_log_main_conf_t *lmcf,njt_str_t *path){
    njt_queue_t                 *q;
    njt_http_dyn_log_file_t     *node;
    njt_open_file_t             *file;
//    njt_pool_cleanup_t *cln;
//    njt_pool_cleanup_file_t        *clnf;
    njt_pool_t                  *pool;
    njt_core_conf_t             *ccf;

    pool = lmcf->pool;
    q = njt_queue_head(&lmcf->file_queue);
    for(;q != njt_queue_sentinel(&lmcf->file_queue);q = njt_queue_next(q)){
        node = njt_queue_data(q,njt_http_dyn_log_file_t,queue);
        if(node->file.name.len == path->len &&
                njt_strncmp(node->file.name.data,path->data,path->len) == 0){
            return node;
        }
    }

    node = njt_pcalloc(pool, sizeof(njt_http_dyn_log_file_t));
    if(node == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"njt_http_log_dyn_open_file alloc mem error");
        return NULL;
    }
    node->ref_count = 0;
    file = &node->file;
    njt_str_copy_pool(pool,file->name,(*path),return NULL);
    file->flush = NULL;
    file->data = NULL;

//    cln = njt_pool_cleanup_add(pool, sizeof(njt_pool_cleanup_file_t)); // 处理无使用场景下，文件句柄关闭的问题，存在double free 问题，暂由代码逻辑保证
//    if (cln == NULL) {
//        return NULL;
//    }

    file->fd = njt_open_file(file->name.data,NJT_FILE_APPEND,
                               NJT_FILE_CREATE_OR_OPEN,NJT_FILE_DEFAULT_ACCESS);

    if (file->fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                      njt_open_file_n " \"%V\" failed",
                      &file->name);
        return  NULL;
    }

    //add by clb, should set file own is real worker user
    if(njt_is_privileged_agent){
        ccf = (njt_core_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_core_module);
        if (ccf && ccf->user != (uid_t) NJT_CONF_UNSET_UINT) {
            if(strncmp(ccf->username, "root", 4) != 0){
                if (fchown(file->fd,ccf->user, ccf->group) == -1) {
                    njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                                    "privileage chown file %V failed", &file->name);
                }
            }
        }
    }
    //end add by clb

#if !(NJT_WIN32)
    if (fcntl(file->fd, F_SETFD, FD_CLOEXEC) == -1) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                      "fcntl(FD_CLOEXEC) \"%V\" failed",
                      &file->name);
        return  NULL;
    }
#endif
//    cln->handler = njt_pool_cleanup_file;
//    clnf = cln->data;
//
//    clnf->fd = file->fd;
//    clnf->name = file->name.data;
//    clnf->log = pool->log;

    njt_queue_insert_head(&lmcf->file_queue,&node->queue);

    return node;

}

njt_int_t
njt_http_check_variable_index(njt_conf_t *cf, njt_str_t *name)
{
    njt_uint_t                  i;
    njt_http_core_main_conf_t  *cmcf;
    njt_hash_key_t             *key;
    njt_http_variable_t        *v, *pv;

    if (name->len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NJT_ERROR;
    }

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    if (cmcf == NULL || cmcf->variables.nelts < 1  || cmcf->variables.elts == NULL) {
        return NJT_ERROR;
    } else {
        v = cmcf->variables.elts;
        key = cmcf->variables_keys->keys.elts;
        pv = cmcf->prefix_variables.elts;
        for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
            if(name->len == key[i].key.len
                && njt_strncmp(name->data, key[i].key.data,name->len)
                   == 0)
            {
                return NJT_OK;
            }
        }
        for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
            if (name->len >= pv[i].name.len
                && njt_strncmp(name->data, pv[i].name.data, pv[i].name.len)
                   == 0)
            {
                return NJT_OK;
            }
        }
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || njt_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }
    return NJT_ERROR;
}


static njt_int_t
njt_http_log_variable_check(njt_conf_t *cf,njt_str_t *value)
{
    njt_int_t  index;

    index = njt_http_check_variable_index(cf, value);
    if (index == NJT_ERROR) {
        njt_log_error(NJT_LOG_WARN, njt_cycle->log, 0,"not found var \"%V\"",value);
        return NJT_ERROR;
    }
    return NJT_OK;
}

static char *
njt_http_log_check_format(njt_conf_t *cf, njt_array_t *flushes,
                            njt_array_t *ops, njt_array_t *args, njt_uint_t s)
{
    u_char              *data, ch;
    size_t               i;
    njt_str_t           *value, var;
    njt_uint_t           bracket;
    njt_http_log_var_t  *v;

    value = args->elts;

    if (s < args->nelts && njt_strncmp(value[s].data, "escape=", 7) == 0) {
        data = value[s].data + 7;
        s++;
    }
    for ( /* void */ ; s < args->nelts; s++) {
        i = 0;
        while (i < value[s].len) {
            data = &value[s].data[i];

            if (value[s].data[i] == '$') {

                if (++i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    bracket = 1;

                    if (++i == value[s].len) {
                        goto invalid;
                    }

                    var.data = &value[s].data[i];

                } else {
                    bracket = 0;
                    var.data = &value[s].data[i];
                }

                for (var.len = 0; i < value[s].len; i++, var.len++) {
                    ch = value[s].data[i];

                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;
                        break;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || ch == '_')
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return NJT_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                for (v = njt_http_log_vars; v->name.len; v++) {

                    if (v->name.len == var.len
                        && njt_strncmp(v->name.data, var.data, var.len) == 0)
                    {
                        goto found;
                    }
                }

                if (njt_http_log_variable_check(cf, &var)!= NJT_OK){
                    return NJT_CONF_ERROR;
                }

                found:

                continue;
            }

            i++;

            while (i < value[s].len && value[s].data[i] != '$') {
                i++;
            }
        }
    }

    return NJT_CONF_OK;

    invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NJT_CONF_ERROR;
}



njt_int_t njt_http_log_dyn_set_log(njt_pool_t *pool, njt_http_dyn_access_api_loc_t *data,njt_http_conf_ctx_t* ctx,njt_str_t * msg,njt_uint_t msg_capacity)
{
    njt_http_log_loc_conf_t *llcf,old_cf;
    njt_http_core_loc_conf_t *clcf;
    njt_uint_t                         i,j, n;
    njt_str_t                          name, *s,full_name;
    njt_http_log_t                    *log;
    njt_syslog_peer_t                 *peer;
    njt_http_log_fmt_t                *fmt;
    njt_http_log_main_conf_t          *lmcf;
    njt_http_script_compile_t          sc;
    u_char * end;
    njt_conf_t *cf;
    njt_http_dyn_log_file_t *file;
    njt_http_dyn_access_log_conf_t *log_cf;

    njt_int_t rc;
    njt_int_t var_count = 0;
    njt_conf_t cf_data = {
            .pool = pool,
            .temp_pool = pool,
            .cycle = (njt_cycle_t*)njt_cycle,
            .log = njt_cycle->log,
            .ctx = ctx,
    };
    cf = &cf_data;

    llcf = njt_http_conf_get_module_loc_conf( cf ,njt_http_log_module);
    if(llcf == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"location module conf was not found.");
        end = njt_snprintf(msg->data,msg_capacity-1," location module conf was not found.");
        msg->len = end - msg->data;
        return NJT_ERROR;
    }

    old_cf = *llcf; //备份原始配置
    clcf = njt_http_conf_get_module_loc_conf( cf ,njt_http_core_module);
    if(clcf == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"core module conf was not found.");
        end = njt_snprintf(msg->data,msg_capacity-1," core module conf was not found.");
        msg->len = end - msg->data;
        return NJT_ERROR;
    }


    rc = njt_sub_pool(clcf->pool,pool);

    if(NJT_OK != rc){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"sub pool err happened");
        end = njt_snprintf(msg->data,msg_capacity-1," sub pool err happened");
        msg->len = end - msg->data;
        return NJT_ERROR;
    }
    llcf->off = data->log_on?0:1;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"set %V access log to %ui",&clcf->full_name,data->log_on);
    llcf->logs = njt_array_create(cf->pool, 2, sizeof(njt_http_log_t));
    if (llcf->logs == NULL) {
        end = njt_snprintf(msg->data,msg_capacity-1," create array error.");
        msg->len = end - msg->data;
        goto error ;
    }

    llcf->dynamic = 1;
    if(!data->log_on){
        // 成功释放原始资源
        if( old_cf.logs != NULL ){
            if(old_cf.dynamic){
                njt_destroy_pool(old_cf.logs->pool);
            }
        }
        return NJT_OK;
    }
    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_log_module);

    log_cf = data->logs.elts;
    if(data->logs.nelts < 1){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"set enable access log,but accessLogs is NULL");
        end = njt_snprintf(msg->data,msg_capacity-1," set enable access log,but accessLogs is NULL");
        msg->len = end - msg->data;
        goto error ;
    }
    for(j = 0 ; j < data->logs.nelts ; ++j ){

        if(log_cf[j].path.len < 1){
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,"access log path not conf continue");
            continue;
        }
        log = njt_array_push(llcf->logs); // 动态释放log
        if (log == NULL) {
            end = njt_snprintf(msg->data,msg_capacity-1," push log error");
            msg->len = end - msg->data;
            goto error ;
        }
        njt_memzero(log, sizeof(njt_http_log_t));
        njt_str_copy_pool(pool,log->path,log_cf[j].path,goto error);
        if (log_cf[j].path.len > 7 && njt_strncmp(log_cf[j].path.data, "syslog:", 7) == 0) {

            peer = njt_pcalloc(cf->pool, sizeof(njt_syslog_peer_t));
            if (peer == NULL) {
                end = njt_snprintf(msg->data,msg_capacity-1," syslog：alloc error.");
                msg->len = end - msg->data;
                goto error ;
            }
            cf->args = njt_array_create(cf->pool,2, sizeof(njt_str_t));
            if (cf->args == NULL) {
                end = njt_snprintf(msg->data,msg_capacity-1," %V：create args error.", &log_cf[j].path);
                msg->len = end - msg->data;
                goto error ;
            }
            s = njt_array_push_n(cf->args,2);
            if (s == NULL) {
                end = njt_snprintf(msg->data,msg_capacity-1," %V: create args error2.",&log_cf[j].path);
                msg->len = end - msg->data;
                goto error ;
            }
            njt_str_null(s);
            ++s;
            njt_str_copy_pool(pool,(*s),log_cf[j].path,return NJT_ERROR);
            if (njt_syslog_process_conf(cf, peer) != NJT_CONF_OK) {
                end = njt_snprintf(msg->data,msg_capacity-1," %V:create args error.",&log_cf[j].path);
                msg->len = end - msg->data;
                goto error ;
            }

            log->syslog_peer = peer;
            goto process_formats;
        }

        n = njt_http_script_variables_count(&log_cf[j].path);
        var_count += n;
        full_name = log_cf[j].path;

        njt_str_t  *prefix = &cf->cycle->prefix;

        if (njt_get_full_name(cf->pool, prefix, &full_name) != NJT_OK) {
            end = njt_snprintf(msg->data,msg_capacity-1," %V: conf full name error.",&log_cf[j].path);
            msg->len = end - msg->data;
            goto error ;
        }
        if (n == 0) {
            file = njt_http_log_dyn_open_file(lmcf,&full_name);
            if (file == NULL) {
                end = njt_snprintf(msg->data,msg_capacity-1," %V: open file error.",&log_cf[j].path);
                msg->len = end - msg->data;
                goto error ;
            }
            njt_http_log_dyn_using_file(cf->pool,file);
            log->file = &file->file;

        } else {
            log->script = njt_pcalloc(cf->pool, sizeof(njt_http_log_script_t));
            if (log->script == NULL) {
                end = njt_snprintf(msg->data,msg_capacity-1," %V: alloc error.", &full_name);
                msg->len = end - msg->data;
                goto error ;
            }

            njt_memzero(&sc, sizeof(njt_http_script_compile_t));
            sc.cf = cf;
            sc.source = &full_name;
            sc.lengths = &log->script->lengths;
            sc.values = &log->script->values;
            sc.variables = n;
            sc.complete_lengths = 1;
            sc.complete_values = 1;
            if (njt_http_script_compile(&sc) != NJT_OK) {
                end = njt_snprintf(msg->data,msg_capacity-1," compile script error.");
                msg->len = end - msg->data;
                goto error ;
            }
        }

        process_formats:

        if (log_cf[j].format.len > 0) {
            name = log_cf[j].format;
        } else {
            njt_str_set(&name, "combined");
        }

        fmt = lmcf->formats.elts;
        for (i = 0; i < lmcf->formats.nelts; i++) {
            if (fmt[i].name.len == name.len
                && njt_strncasecmp(fmt[i].name.data, name.data,name.len) == 0)
            {
                log->format = &fmt[i];
                break;
            }
        }

        if (log->format == NULL) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "unknown log format \"%V\"", &name);
            end = njt_snprintf(msg->data,msg_capacity-1, " unknown log format \"%V\"", &name);
            msg->len = end - msg->data;
            goto error ;
        }
    }

    if(var_count>0){
        rc = njt_http_variables_init_vars_dyn(cf);
        if(rc!=NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "init vars error");
            end = njt_snprintf(msg->data,msg_capacity-1,"init vars error");
            msg->len = end - msg->data;
            goto error ;
        }
    }
    // 成功释放原始资源
    if( old_cf.logs != NULL ){
        if(old_cf.dynamic){
            njt_destroy_pool(old_cf.logs->pool);
        }
//        old_cf.logs = NULL;
    }
    return NJT_OK;

    error:
    // 失败还原配置
    *llcf = old_cf;
    return NJT_ERROR;
}

njt_int_t njt_http_log_dyn_set_format(njt_http_dyn_access_log_format_t *data)
{
    njt_http_log_main_conf_t *lmcf;
    njt_str_t           *value;
    njt_uint_t           i,index;
    njt_http_log_fmt_t  *fmt,old_fmt,new_format;
    njt_conf_t cfd,*cf;
    njt_int_t rc,update;
    static char * rs;
    njt_http_conf_ctx_t ctx;
    njt_http_core_main_conf_t *cmcf;
    njt_http_core_srv_conf_t **cscfp;

    update = 0;
    njt_pool_t *pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        return NJT_ERROR;
    }
    rc = njt_sub_pool(njt_cycle->pool,pool);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }
    cf= &cfd;
    njt_memzero(cf, sizeof(njt_conf_t));
    cfd.pool = pool;
    cfd.temp_pool = pool;
    cfd.cycle = (njt_cycle_t*)njt_cycle;
    cfd.log = njt_cycle->log;
    cmcf = njt_http_cycle_get_module_main_conf(njt_cycle,njt_http_core_module);
    if(!cmcf || cmcf->servers.nelts == 0){
        // 不存在server
        njt_log_error(NJT_LOG_ERR, cf->log, 0,"servers is empty");
        return NJT_ERROR;
    }
    cscfp = cmcf->servers.elts;
    if(cscfp == NULL){
        njt_log_error(NJT_LOG_ERR, cf->log, 0,"not find server in http{}");
        goto err;
    }
    ctx = *(*cscfp)->ctx;
    cfd.ctx = &ctx;

    lmcf = njt_http_cycle_get_module_main_conf(njt_cycle,njt_http_log_module);
    if(!lmcf){
        // 未加载log_module
        njt_log_error(NJT_LOG_ERR, cf->log, 0,"unload njt_http_log_module");
        return NJT_ERROR;
    }
    cf->args = njt_array_create(cf->pool,3, sizeof(njt_str_t));
    if(cf->args == NULL){
        goto err;
    }
    if(data->escape.len > 0 ){
        value = njt_array_push_n(cf->args,3);
    } else{
        value = njt_array_push_n(cf->args,2);
    }

    if(value == NULL){
        goto err;
    }
    njt_str_copy_pool(pool,value[0],data->name, goto err);

    index =1;
    if(data->escape.len > 0 ){
        njt_str_t prefix = njt_string("escape=");
        data->escape.len++;
        njt_str_concat(pool,value[index],prefix, data->escape,goto err);
        data->escape.len--;
        value[index].len--;
        value[index].data[value[index].len]='\0';
        ++index;
    }
    njt_str_copy_pool(pool,value[index],data->format, goto err);
    value = cf->args->elts;

    njt_memzero(&old_fmt, sizeof(njt_http_log_fmt_t));
    njt_memzero(&new_format, sizeof(njt_http_log_fmt_t));
    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == data->name.len
            && njt_strncmp(fmt[i].name.data,  data->name.data,data->name.len) == 0){
            update =1;
            fmt = &fmt[i];
            old_fmt = *fmt;
            break;
        }
    }
    if(!update){
        if(lmcf->formats.nelts == lmcf->formats.nalloc){
            // www: insufficient capacity
            njt_log_error(NJT_LOG_ERR, cf->log, 0,"add format error, insufficient capacity. Up to %ud formats",lmcf->formats.nalloc);
            goto err;
        }

        fmt = &new_format;
    }
    njt_memzero(fmt, sizeof(njt_http_log_fmt_t));
    fmt->dynamic = 1;
    fmt->name= value[0];
    index = 1;
    if(data->escape.len > 0 ){
        njt_str_copy_pool(pool,fmt->escape, data->escape, goto err);
        ++index;
    }
    fmt->format= value[index];

    fmt->flushes = njt_array_create(cf->pool, 4, sizeof(njt_int_t));
    if (fmt->flushes == NULL) {
        goto err;
    }

    fmt->ops = njt_array_create(cf->pool, 16, sizeof(njt_http_log_op_t));
    if (fmt->ops == NULL) {
        goto err;
    }

    if(njt_http_log_check_format(cf, fmt->flushes, fmt->ops, cf->args, 1) != NJT_OK){
        goto err;
    }
    rs=njt_http_log_compile_format(cf, fmt->flushes, fmt->ops, cf->args, 1);
    if(rs == NJT_CONF_ERROR){
        goto err;
    }
    rc = njt_http_variables_init_vars_dyn(cf);
    if(rc!=NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "init vars error");
        goto err ;
    }
    if(update){
        if(old_fmt.dynamic){
            njt_destroy_pool(old_fmt.ops->pool);
        }
    }else{
        fmt = njt_array_push(&lmcf->formats);
        if (fmt == NULL) {
            goto err;
        }
        *fmt = new_format;
    }
    return NJT_OK;

    err:
    if(update) {
        *fmt = old_fmt;
    }
    njt_destroy_pool(pool);
    return NJT_ERROR;
}


#endif
