
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


static char *njt_error_log(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_log_set_levels(njt_conf_t *cf, njt_log_t *log);
static void njt_log_insert(njt_log_t *log, njt_log_t *new_log);


#if (NJT_DEBUG)

static void njt_log_memory_writer(njt_log_t *log, njt_uint_t level,
    u_char *buf, size_t len);
static void njt_log_memory_cleanup(void *data);


typedef struct {
    u_char        *start;
    u_char        *end;
    u_char        *pos;
    njt_atomic_t   written;
} njt_log_memory_buf_t;

#endif


static njt_command_t  njt_errlog_commands[] = {

    { njt_string("error_log"),
      NJT_MAIN_CONF|NJT_CONF_1MORE,
      njt_error_log,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_errlog_module_ctx = {
    njt_string("errlog"),
    NULL,
    NULL
};


njt_module_t  njt_errlog_module = {
    NJT_MODULE_V1,
    &njt_errlog_module_ctx,                /* module context */
    njt_errlog_commands,                   /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_log_t        njt_log;
static njt_open_file_t  njt_log_file;
njt_uint_t              njt_use_stderr = 1;


static njt_str_t err_levels[] = {
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

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_stream"
};


#if (NJT_HAVE_VARIADIC_MACROS)

void
njt_log_error_core(njt_uint_t level, njt_log_t *log, njt_err_t err,
    const char *fmt, ...)

#else

void
njt_log_error_core(njt_uint_t level, njt_log_t *log, njt_err_t err,
    const char *fmt, va_list args)

#endif
{
#if (NJT_HAVE_VARIADIC_MACROS)
    va_list      args;
#endif
    u_char      *p, *last, *msg;
    ssize_t      n;
    njt_uint_t   wrote_stderr, debug_connection;
    u_char       errstr[NJT_MAX_ERROR_STR];

    njt_log_intercept_pt    log_intercept = NULL; // openresty patch

    last = errstr + NJT_MAX_ERROR_STR;

    p = njt_cpymem(errstr, njt_cached_err_log_time.data,
                   njt_cached_err_log_time.len);

    p = njt_slprintf(p, last, " [%V] ", &err_levels[level]);

    /* pid#tid */
    p = njt_slprintf(p, last, "%P#" NJT_TID_T_FMT ": ",
                    njt_log_pid, njt_log_tid);

    if (log->connection) {
        p = njt_slprintf(p, last, "*%uA ", log->connection);
    }

    msg = p;

#if (NJT_HAVE_VARIADIC_MACROS)

    va_start(args, fmt);
    p = njt_vslprintf(p, last, fmt, args);
    va_end(args);

#else

    p = njt_vslprintf(p, last, fmt, args);

#endif

    if (err) {
        p = njt_log_errno(p, last, err);
    }

    if (level != NJT_LOG_DEBUG && log->handler) {
        p = log->handler(log, p, last - p);
    }

    if (p > last - NJT_LINEFEED_SIZE) {
        p = last - NJT_LINEFEED_SIZE;
    }

    // openresty patch
    if (njt_cycle) {
        log_intercept = njt_cycle->intercept_error_log_handler;
    }

    if (log_intercept && !njt_cycle->entered_logger) {
        njt_cycle->entered_logger = 1;
        log_intercept(log, level, errstr, p - errstr);
        njt_cycle->entered_logger = 0;
    }
    // openresty patch end

    njt_linefeed(p);

    wrote_stderr = 0;
    debug_connection = (log->log_level & NJT_LOG_DEBUG_CONNECTION) != 0;

    while (log) {

        if (log->log_level < level && !debug_connection) {
            break;
        }

        if (log->writer) {
            log->writer(log, level, errstr, p - errstr);
            goto next;
        }

        if (njt_time() == log->disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            goto next;
        }

        n = njt_write_fd(log->file->fd, errstr, p - errstr);

        if (n == -1 && njt_errno == NJT_ENOSPC) {
            log->disk_full_time = njt_time();
        }

        if (log->file->fd == njt_stderr) {
            wrote_stderr = 1;
        }

    next:

        log = log->next;
    }

    if (!njt_use_stderr
        || level > NJT_LOG_WARN
        || wrote_stderr)
    {
        return;
    }

    msg -= (7 + err_levels[level].len + 3);

    (void) njt_sprintf(msg, "njet: [%V] ", &err_levels[level]);

    (void) njt_write_console(njt_stderr, msg, p - msg);
}


#if !(NJT_HAVE_VARIADIC_MACROS)

void njt_cdecl
njt_log_error(njt_uint_t level, njt_log_t *log, njt_err_t err,
    const char *fmt, ...)
{
    va_list  args;

    if (log->log_level >= level) {
        va_start(args, fmt);
        njt_log_error_core(level, log, err, fmt, args);
        va_end(args);
    }
}


void njt_cdecl
njt_log_debug_core(njt_log_t *log, njt_err_t err, const char *fmt, ...)
{
    va_list  args;

    va_start(args, fmt);
    njt_log_error_core(NJT_LOG_DEBUG, log, err, fmt, args);
    va_end(args);
}

#endif


void njt_cdecl
njt_log_abort(njt_err_t err, const char *fmt, ...)
{
    u_char   *p;
    va_list   args;
    u_char    errstr[NJT_MAX_CONF_ERRSTR];

    va_start(args, fmt);
    p = njt_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    njt_log_error(NJT_LOG_ALERT, njt_cycle->log, err,
                  "%*s", p - errstr, errstr);
}


void njt_cdecl
njt_log_stderr(njt_err_t err, const char *fmt, ...)
{
    u_char   *p, *last;
    va_list   args;
    u_char    errstr[NJT_MAX_ERROR_STR];

    last = errstr + NJT_MAX_ERROR_STR;

    p = njt_cpymem(errstr, "njet: ", 7);

    va_start(args, fmt);
    p = njt_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = njt_log_errno(p, last, err);
    }

    if (p > last - NJT_LINEFEED_SIZE) {
        p = last - NJT_LINEFEED_SIZE;
    }

    njt_linefeed(p);

    (void) njt_write_console(njt_stderr, errstr, p - errstr);
}


u_char *
njt_log_errno(u_char *buf, u_char *last, njt_err_t err)
{
    if (buf > last - 50) {

        /* leave a space for an error code */

        buf = last - 50;
        *buf++ = '.';
        *buf++ = '.';
        *buf++ = '.';
    }

#if (NJT_WIN32)
    buf = njt_slprintf(buf, last, ((unsigned) err < 0x80000000)
                                       ? " (%d: " : " (%Xd: ", err);
#else
    buf = njt_slprintf(buf, last, " (%d: ", err);
#endif

    buf = njt_strerror(err, buf, last - buf);

    if (buf < last) {
        *buf++ = ')';
    }

    return buf;
}


njt_log_t *
njt_log_init(u_char *prefix, u_char *error_log)
{
    u_char  *p, *name;
    size_t   nlen, plen;

    njt_log.file = &njt_log_file;
    njt_log.log_level = NJT_LOG_NOTICE;

    if (error_log == NULL) {
        error_log = (u_char *) NJT_ERROR_LOG_PATH;
    }

    name = error_log;
    nlen = njt_strlen(name);

    if (nlen == 0) {
        njt_log_file.fd = njt_stderr;
        return &njt_log;
    }

    p = NULL;

#if (NJT_WIN32)
    if (name[1] != ':') {
#else
    if (name[0] != '/') {
#endif

        if (prefix) {
            plen = njt_strlen(prefix);

        } else {
#ifdef NJT_PREFIX
            prefix = (u_char *) NJT_PREFIX;
            plen = njt_strlen(prefix);
#else
            plen = 0;
#endif
        }

        if (plen) {
            name = malloc(plen + nlen + 2);
            if (name == NULL) {
                return NULL;
            }

            p = njt_cpymem(name, prefix, plen);

            if (!njt_path_separator(*(p - 1))) {
                *p++ = '/';
            }

            njt_cpystrn(p, error_log, nlen + 1);

            p = name;
        }
    }

    njt_log_file.fd = njt_open_file(name, NJT_FILE_APPEND,
                                    NJT_FILE_CREATE_OR_OPEN,
                                    NJT_FILE_DEFAULT_ACCESS);

    if (njt_log_file.fd == NJT_INVALID_FILE) {
        njt_log_stderr(njt_errno,
                       "[alert] could not open error log file: "
                       njt_open_file_n " \"%s\" failed", name);
#if (NJT_WIN32)
        njt_event_log(njt_errno,
                       "could not open error log file: "
                       njt_open_file_n " \"%s\" failed", name);
#endif

        njt_log_file.fd = njt_stderr;
    }

    if (p) {
        njt_free(p);
    }

    return &njt_log;
}


njt_int_t
njt_log_open_default(njt_cycle_t *cycle)
{
    njt_log_t  *log;

    if (njt_log_get_file_log(&cycle->new_log) != NULL) {
        return NJT_OK;
    }

    if (cycle->new_log.log_level != 0) {
        /* there are some error logs, but no files */

        log = njt_pcalloc(cycle->pool, sizeof(njt_log_t));
        if (log == NULL) {
            return NJT_ERROR;
        }

    } else {
        /* no error logs at all */
        log = &cycle->new_log;
    }

    log->log_level = NJT_LOG_ERR;

    log->file = njt_conf_open_file(cycle, &cycle->error_log);
    if (log->file == NULL) {
        return NJT_ERROR;
    }

    if (log != &cycle->new_log) {
        njt_log_insert(&cycle->new_log, log);
    }

    return NJT_OK;
}


njt_int_t
njt_log_redirect_stderr(njt_cycle_t *cycle)
{
    njt_fd_t  fd;

    if (cycle->log_use_stderr) {
        return NJT_OK;
    }

    /* file log always exists when we are called */
    fd = njt_log_get_file_log(cycle->log)->file->fd;

    if (fd != njt_stderr) {
        if (njt_set_stderr(fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          njt_set_stderr_n " failed");

            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


njt_log_t *
njt_log_get_file_log(njt_log_t *head)
{
    njt_log_t  *log;

    for (log = head; log; log = log->next) {
        if (log->file != NULL) {
            return log;
        }
    }

    return NULL;
}


static char *
njt_log_set_levels(njt_conf_t *cf, njt_log_t *log)
{
    njt_uint_t   i, n, d, found;
    njt_str_t   *value;

    if (cf->args->nelts == 2) {
        log->log_level = NJT_LOG_ERR;
        return NJT_CONF_OK;
    }

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {
        found = 0;

        for (n = 1; n <= NJT_LOG_DEBUG; n++) {
            if (njt_strcmp(value[i].data, err_levels[n].data) == 0) {

                if (log->log_level != 0) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%V\"",
                                       &value[i]);
                    return NJT_CONF_ERROR;
                }

                log->log_level = n;
                found = 1;
                break;
            }
        }

        for (n = 0, d = NJT_LOG_DEBUG_FIRST; d <= NJT_LOG_DEBUG_LAST; d <<= 1) {
            if (njt_strcmp(value[i].data, debug_levels[n++]) == 0) {
                if (log->log_level & ~NJT_LOG_DEBUG_ALL) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "invalid log level \"%V\"",
                                       &value[i]);
                    return NJT_CONF_ERROR;
                }

                log->log_level |= d;
                found = 1;
                break;
            }
        }


        if (!found) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid log level \"%V\"", &value[i]);
            return NJT_CONF_ERROR;
        }
    }

    if (log->log_level == NJT_LOG_DEBUG) {
        log->log_level = NJT_LOG_DEBUG_ALL;
    }

    return NJT_CONF_OK;
}


static char *
njt_error_log(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_log_t  *dummy;

    dummy = &cf->cycle->new_log;

    return njt_log_set_log(cf, &dummy);
}


char *
njt_log_set_log(njt_conf_t *cf, njt_log_t **head)
{
    njt_log_t          *new_log;
    njt_str_t          *value, name;
    njt_syslog_peer_t  *peer;

    if (*head != NULL && (*head)->log_level == 0) {
        new_log = *head;

    } else {

        new_log = njt_pcalloc(cf->pool, sizeof(njt_log_t));
        if (new_log == NULL) {
            return NJT_CONF_ERROR;
        }

        if (*head == NULL) {
            *head = new_log;
        }
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "stderr") == 0) {
        njt_str_null(&name);
	if(cf->cycle == NULL) {
	   njt_conf_log_error(NJT_LOG_EMERG, cf, 0,"cf->cycle is null");
	   return NJT_CONF_ERROR;
	}
        cf->cycle->log_use_stderr = 1;

        new_log->file = njt_conf_open_file(cf->cycle, &name);
        if (new_log->file == NULL) {
            return NJT_CONF_ERROR;
        }

    } else if (njt_strncmp(value[1].data, "memory:", 7) == 0) {

#if (NJT_DEBUG)
        size_t                 size, needed;
        njt_pool_cleanup_t    *cln;
        njt_log_memory_buf_t  *buf;

        value[1].len -= 7;
        value[1].data += 7;

        needed = sizeof("MEMLOG  :" NJT_LINEFEED)
                 + cf->conf_file->file.name.len
                 + NJT_SIZE_T_LEN
                 + NJT_INT_T_LEN
                 + NJT_MAX_ERROR_STR;

        size = njt_parse_size(&value[1]);

        if (size == (size_t) NJT_ERROR || size < needed) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid buffer size \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

        buf = njt_pcalloc(cf->pool, sizeof(njt_log_memory_buf_t));
        if (buf == NULL) {
            return NJT_CONF_ERROR;
        }

        buf->start = njt_pnalloc(cf->pool, size);
        if (buf->start == NULL) {
            return NJT_CONF_ERROR;
        }

        buf->end = buf->start + size;

        buf->pos = njt_slprintf(buf->start, buf->end, "MEMLOG %uz %V:%ui%N",
                                size, &cf->conf_file->file.name,
                                cf->conf_file->line);

        njt_memset(buf->pos, ' ', buf->end - buf->pos);

        cln = njt_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NJT_CONF_ERROR;
        }

        cln->data = new_log;
        cln->handler = njt_log_memory_cleanup;

        new_log->writer = njt_log_memory_writer;
        new_log->wdata = buf;

#else
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "njet was built without debug support");
        return NJT_CONF_ERROR;
#endif

    } else if (njt_strncmp(value[1].data, "syslog:", 7) == 0) {
        peer = njt_pcalloc(cf->pool, sizeof(njt_syslog_peer_t));
        if (peer == NULL) {
            return NJT_CONF_ERROR;
        }

        if (njt_syslog_process_conf(cf, peer) != NJT_CONF_OK) {
            return NJT_CONF_ERROR;
        }

        new_log->writer = njt_syslog_writer;
        new_log->wdata = peer;

    } else {
        new_log->file = njt_conf_open_file(cf->cycle, &value[1]);
        if (new_log->file == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    if (njt_log_set_levels(cf, new_log) != NJT_CONF_OK) {
        return NJT_CONF_ERROR;
    }

    if (*head != new_log) {
        njt_log_insert(*head, new_log);
    }

    return NJT_CONF_OK;
}


static void
njt_log_insert(njt_log_t *log, njt_log_t *new_log)
{
    njt_log_t  tmp;

    if (new_log->log_level > log->log_level) {

        /*
         * list head address is permanent, insert new log after
         * head and swap its contents with head
         */

        tmp = *log;
        *log = *new_log;
        *new_log = tmp;

        log->next = new_log;
        return;
    }

    while (log->next) {
        if (new_log->log_level > log->next->log_level) {
            new_log->next = log->next;
            log->next = new_log;
            return;
        }

        log = log->next;
    }

    log->next = new_log;
}


#if (NJT_DEBUG)

static void
njt_log_memory_writer(njt_log_t *log, njt_uint_t level, u_char *buf,
    size_t len)
{
    u_char                *p;
    size_t                 avail, written;
    njt_log_memory_buf_t  *mem;

    mem = log->wdata;

    if (mem == NULL) {
        return;
    }

    written = njt_atomic_fetch_add(&mem->written, len);

    p = mem->pos + written % (mem->end - mem->pos);

    avail = mem->end - p;

    if (avail >= len) {
        njt_memcpy(p, buf, len);

    } else {
        njt_memcpy(p, buf, avail);
        njt_memcpy(mem->pos, buf + avail, len - avail);
    }
}


static void
njt_log_memory_cleanup(void *data)
{
    njt_log_t *log = data;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, log, 0, "destroy memory log buffer");

    log->wdata = NULL;
}

#endif
