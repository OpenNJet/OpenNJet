
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#if 0

typedef struct {
    njt_buf_t     *buf;
    size_t         size;
    njt_pool_t    *pool;
    size_t         alloc_size;
    njt_chain_t  **last_out;
} njt_http_autoindex_ctx_t;

#endif


typedef struct {
    njt_str_t      name;
    size_t         utf_len;
    size_t         escape;
    size_t         escape_html;

    unsigned       dir:1;
    unsigned       file:1;

    time_t         mtime;
    off_t          size;
} njt_http_autoindex_entry_t;


typedef struct {
    njt_flag_t     enable;
    njt_uint_t     format;
    njt_flag_t     localtime;
    njt_flag_t     exact_size;
} njt_http_autoindex_loc_conf_t;


#define NJT_HTTP_AUTOINDEX_HTML         0
#define NJT_HTTP_AUTOINDEX_JSON         1
#define NJT_HTTP_AUTOINDEX_JSONP        2
#define NJT_HTTP_AUTOINDEX_XML          3

#define NJT_HTTP_AUTOINDEX_PREALLOCATE  50

#define NJT_HTTP_AUTOINDEX_NAME_LEN     50


static njt_buf_t *njt_http_autoindex_html(njt_http_request_t *r,
    njt_array_t *entries);
static njt_buf_t *njt_http_autoindex_json(njt_http_request_t *r,
    njt_array_t *entries, njt_str_t *callback);
static njt_int_t njt_http_autoindex_jsonp_callback(njt_http_request_t *r,
    njt_str_t *callback);
static njt_buf_t *njt_http_autoindex_xml(njt_http_request_t *r,
    njt_array_t *entries);

static int njt_libc_cdecl njt_http_autoindex_cmp_entries(const void *one,
    const void *two);
static njt_int_t njt_http_autoindex_error(njt_http_request_t *r,
    njt_dir_t *dir, njt_str_t *name);

static njt_int_t njt_http_autoindex_init(njt_conf_t *cf);
static void *njt_http_autoindex_create_loc_conf(njt_conf_t *cf);
static char *njt_http_autoindex_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);


static njt_conf_enum_t  njt_http_autoindex_format[] = {
    { njt_string("html"), NJT_HTTP_AUTOINDEX_HTML },
    { njt_string("json"), NJT_HTTP_AUTOINDEX_JSON },
    { njt_string("jsonp"), NJT_HTTP_AUTOINDEX_JSONP },
    { njt_string("xml"), NJT_HTTP_AUTOINDEX_XML },
    { njt_null_string, 0 }
};


static njt_command_t  njt_http_autoindex_commands[] = {

    { njt_string("autoindex"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_autoindex_loc_conf_t, enable),
      NULL },

    { njt_string("autoindex_format"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_autoindex_loc_conf_t, format),
      &njt_http_autoindex_format },

    { njt_string("autoindex_localtime"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_autoindex_loc_conf_t, localtime),
      NULL },

    { njt_string("autoindex_exact_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_autoindex_loc_conf_t, exact_size),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_autoindex_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_autoindex_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_autoindex_create_loc_conf,    /* create location configuration */
    njt_http_autoindex_merge_loc_conf      /* merge location configuration */
};


njt_module_t  njt_http_autoindex_module = {
    NJT_MODULE_V1,
    &njt_http_autoindex_module_ctx,        /* module context */
    njt_http_autoindex_commands,           /* module directives */
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


static njt_int_t
njt_http_autoindex_handler(njt_http_request_t *r)
{
    u_char                         *last, *filename;
    size_t                          len, allocated, root;
    njt_err_t                       err;
    njt_buf_t                      *b;
    njt_int_t                       rc;
    njt_str_t                       path, callback;
    njt_dir_t                       dir;
    njt_uint_t                      level, format;
    njt_pool_t                     *pool;
    njt_chain_t                     out;
    njt_array_t                     entries;
    njt_http_autoindex_entry_t     *entry;
    njt_http_autoindex_loc_conf_t  *alcf;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NJT_DECLINED;
    }

    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD))) {
        return NJT_DECLINED;
    }

    alcf = njt_http_get_module_loc_conf(r, njt_http_autoindex_module);

    if (!alcf->enable) {
        return NJT_DECLINED;
    }

    rc = njt_http_discard_request_body(r);

    if (rc != NJT_OK) {
        return rc;
    }

    last = njt_http_map_uri_to_path(r, &path, &root,
                                    NJT_HTTP_AUTOINDEX_PREALLOCATE);
    if (last == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;
    path.len = last - path.data;
    if (path.len > 1) {
        path.len--;
    }
    path.data[path.len] = '\0';

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http autoindex: \"%s\"", path.data);

    format = alcf->format;

    if (format == NJT_HTTP_AUTOINDEX_JSONP) {
        if (njt_http_autoindex_jsonp_callback(r, &callback) != NJT_OK) {
            return NJT_HTTP_BAD_REQUEST;
        }

        if (callback.len == 0) {
            format = NJT_HTTP_AUTOINDEX_JSON;
        }
    }

    if (njt_open_dir(&path, &dir) == NJT_ERROR) {
        err = njt_errno;

        if (err == NJT_ENOENT
            || err == NJT_ENOTDIR
            || err == NJT_ENAMETOOLONG)
        {
            level = NJT_LOG_ERR;
            rc = NJT_HTTP_NOT_FOUND;

        } else if (err == NJT_EACCES) {
            level = NJT_LOG_ERR;
            rc = NJT_HTTP_FORBIDDEN;

        } else {
            level = NJT_LOG_CRIT;
            rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        njt_log_error(level, r->connection->log, err,
                      njt_open_dir_n " \"%s\" failed", path.data);

        return rc;
    }

#if (NJT_SUPPRESS_WARN)

    /* MSVC thinks 'entries' may be used without having been initialized */
    njt_memzero(&entries, sizeof(njt_array_t));

#endif

    /* TODO: pool should be temporary pool */
    pool = r->pool;

    if (njt_array_init(&entries, pool, 40, sizeof(njt_http_autoindex_entry_t))
        != NJT_OK)
    {
        return njt_http_autoindex_error(r, &dir, &path);
    }

    r->headers_out.status = NJT_HTTP_OK;

    switch (format) {

    case NJT_HTTP_AUTOINDEX_JSON:
        njt_str_set(&r->headers_out.content_type, "application/json");
        break;

    case NJT_HTTP_AUTOINDEX_JSONP:
        njt_str_set(&r->headers_out.content_type, "application/javascript");
        break;

    case NJT_HTTP_AUTOINDEX_XML:
        njt_str_set(&r->headers_out.content_type, "text/xml");
        njt_str_set(&r->headers_out.charset, "utf-8");
        break;

    default: /* NJT_HTTP_AUTOINDEX_HTML */
        njt_str_set(&r->headers_out.content_type, "text/html");
        break;
    }

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        if (njt_close_dir(&dir) == NJT_ERROR) {
            njt_log_error(NJT_LOG_ALERT, r->connection->log, njt_errno,
                          njt_close_dir_n " \"%V\" failed", &path);
        }

        return rc;
    }

    filename = path.data;
    filename[path.len] = '/';

    for ( ;; ) {
        njt_set_errno(0);

        if (njt_read_dir(&dir) == NJT_ERROR) {
            err = njt_errno;

            if (err != NJT_ENOMOREFILES) {
                njt_log_error(NJT_LOG_CRIT, r->connection->log, err,
                              njt_read_dir_n " \"%V\" failed", &path);
                return njt_http_autoindex_error(r, &dir, &path);
            }

            break;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http autoindex file: \"%s\"", njt_de_name(&dir));

        len = njt_de_namelen(&dir);

        if (njt_de_name(&dir)[0] == '.') {
            continue;
        }

        if (!dir.valid_info) {

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + NJT_HTTP_AUTOINDEX_PREALLOCATE;

                filename = njt_pnalloc(pool, allocated);
                if (filename == NULL) {
                    return njt_http_autoindex_error(r, &dir, &path);
                }

                last = njt_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            njt_cpystrn(last, njt_de_name(&dir), len + 1);

            if (njt_de_info(filename, &dir) == NJT_FILE_ERROR) {
                err = njt_errno;

                if (err != NJT_ENOENT && err != NJT_ELOOP) {
                    njt_log_error(NJT_LOG_CRIT, r->connection->log, err,
                                  njt_de_info_n " \"%s\" failed", filename);

                    if (err == NJT_EACCES) {
                        continue;
                    }

                    return njt_http_autoindex_error(r, &dir, &path);
                }

                if (njt_de_link_info(filename, &dir) == NJT_FILE_ERROR) {
                    njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                                  njt_de_link_info_n " \"%s\" failed",
                                  filename);
                    return njt_http_autoindex_error(r, &dir, &path);
                }
            }
        }

        entry = njt_array_push(&entries);
        if (entry == NULL) {
            return njt_http_autoindex_error(r, &dir, &path);
        }

        entry->name.len = len;

        entry->name.data = njt_pnalloc(pool, len + 1);
        if (entry->name.data == NULL) {
            return njt_http_autoindex_error(r, &dir, &path);
        }

        njt_cpystrn(entry->name.data, njt_de_name(&dir), len + 1);

        entry->dir = njt_de_is_dir(&dir);
        entry->file = njt_de_is_file(&dir);
        entry->mtime = njt_de_mtime(&dir);
        entry->size = njt_de_size(&dir);
    }

    if (njt_close_dir(&dir) == NJT_ERROR) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, njt_errno,
                      njt_close_dir_n " \"%V\" failed", &path);
    }

    if (entries.nelts > 1) {
        njt_qsort(entries.elts, (size_t) entries.nelts,
                  sizeof(njt_http_autoindex_entry_t),
                  njt_http_autoindex_cmp_entries);
    }

    switch (format) {

    case NJT_HTTP_AUTOINDEX_JSON:
        b = njt_http_autoindex_json(r, &entries, NULL);
        break;

    case NJT_HTTP_AUTOINDEX_JSONP:
        b = njt_http_autoindex_json(r, &entries, &callback);
        break;

    case NJT_HTTP_AUTOINDEX_XML:
        b = njt_http_autoindex_xml(r, &entries);
        break;

    default: /* NJT_HTTP_AUTOINDEX_HTML */
        b = njt_http_autoindex_html(r, &entries);
        break;
    }

    if (b == NULL) {
        return NJT_ERROR;
    }

    /* TODO: free temporary pool */

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return njt_http_output_filter(r, &out);
}


static njt_buf_t *
njt_http_autoindex_html(njt_http_request_t *r, njt_array_t *entries)
{
    u_char                         *last, scale;
    off_t                           length;
    size_t                          len, entry_len, char_len, escape_html;
    njt_tm_t                        tm;
    njt_buf_t                      *b;
    njt_int_t                       size;
    njt_uint_t                      i, utf8;
    njt_time_t                     *tp;
    njt_http_autoindex_entry_t     *entry;
    njt_http_autoindex_loc_conf_t  *alcf;

    static u_char  title[] =
        "<html>" CRLF
        "<head><title>Index of "
    ;

    static u_char  header[] =
        "</title></head>" CRLF
        "<body>" CRLF
        "<h1>Index of "
    ;

    static u_char  tail[] =
        "</body>" CRLF
        "</html>" CRLF
    ;

    static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    if (r->headers_out.charset.len == 5
        && njt_strncasecmp(r->headers_out.charset.data, (u_char *) "utf-8", 5)
           == 0)
    {
        utf8 = 1;

    } else {
        utf8 = 0;
    }

    escape_html = njt_escape_html(NULL, r->uri.data, r->uri.len);

    len = sizeof(title) - 1
          + r->uri.len + escape_html
          + sizeof(header) - 1
          + r->uri.len + escape_html
          + sizeof("</h1>") - 1
          + sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1
          + sizeof("</pre><hr>") - 1
          + sizeof(tail) - 1;

    entry = entries->elts;
    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = 2 * njt_escape_uri(NULL, entry[i].name.data,
                                             entry[i].name.len,
                                             NJT_ESCAPE_URI_COMPONENT);

        entry[i].escape_html = njt_escape_html(NULL, entry[i].name.data,
                                               entry[i].name.len);

        if (utf8) {
            entry[i].utf_len = njt_utf8_length(entry[i].name.data,
                                               entry[i].name.len);
        } else {
            entry[i].utf_len = entry[i].name.len;
        }

        entry_len = sizeof("<a href=\"") - 1
                  + entry[i].name.len + entry[i].escape
                  + 1                                    /* 1 is for "/" */
                  + sizeof("\">") - 1
                  + entry[i].name.len - entry[i].utf_len
                  + entry[i].escape_html
                  + NJT_HTTP_AUTOINDEX_NAME_LEN + sizeof("&gt;") - 2
                  + sizeof("</a>") - 1
                  + sizeof(" 28-Sep-1970 12:00 ") - 1
                  + 20                                   /* the file size */
                  + 2;

        if (len > NJT_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = njt_cpymem(b->last, title, sizeof(title) - 1);

    if (escape_html) {
        b->last = (u_char *) njt_escape_html(b->last, r->uri.data, r->uri.len);
        b->last = njt_cpymem(b->last, header, sizeof(header) - 1);
        b->last = (u_char *) njt_escape_html(b->last, r->uri.data, r->uri.len);

    } else {
        b->last = njt_cpymem(b->last, r->uri.data, r->uri.len);
        b->last = njt_cpymem(b->last, header, sizeof(header) - 1);
        b->last = njt_cpymem(b->last, r->uri.data, r->uri.len);
    }

    b->last = njt_cpymem(b->last, "</h1>", sizeof("</h1>") - 1);

    b->last = njt_cpymem(b->last, "<hr><pre><a href=\"../\">../</a>" CRLF,
                         sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1);

    alcf = njt_http_get_module_loc_conf(r, njt_http_autoindex_module);
    tp = njt_timeofday();

    for (i = 0; i < entries->nelts; i++) {
        b->last = njt_cpymem(b->last, "<a href=\"", sizeof("<a href=\"") - 1);

        if (entry[i].escape) {
            njt_escape_uri(b->last, entry[i].name.data, entry[i].name.len,
                           NJT_ESCAPE_URI_COMPONENT);

            b->last += entry[i].name.len + entry[i].escape;

        } else {
            b->last = njt_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        if (entry[i].dir) {
            *b->last++ = '/';
        }

        *b->last++ = '"';
        *b->last++ = '>';

        len = entry[i].utf_len;

        if (entry[i].name.len != len) {
            if (len > NJT_HTTP_AUTOINDEX_NAME_LEN) {
                char_len = NJT_HTTP_AUTOINDEX_NAME_LEN - 3 + 1;

            } else {
                char_len = NJT_HTTP_AUTOINDEX_NAME_LEN + 1;
            }

            last = b->last;
            b->last = njt_utf8_cpystrn(b->last, entry[i].name.data,
                                       char_len, entry[i].name.len + 1);

            if (entry[i].escape_html) {
                b->last = (u_char *) njt_escape_html(last, entry[i].name.data,
                                                     b->last - last);
            }

            last = b->last;

        } else {
            if (entry[i].escape_html) {
                if (len > NJT_HTTP_AUTOINDEX_NAME_LEN) {
                    char_len = NJT_HTTP_AUTOINDEX_NAME_LEN - 3;

                } else {
                    char_len = len;
                }

                b->last = (u_char *) njt_escape_html(b->last,
                                                  entry[i].name.data, char_len);
                last = b->last;

            } else {
                b->last = njt_cpystrn(b->last, entry[i].name.data,
                                      NJT_HTTP_AUTOINDEX_NAME_LEN + 1);
                last = b->last - 3;
            }
        }

        if (len > NJT_HTTP_AUTOINDEX_NAME_LEN) {
            b->last = njt_cpymem(last, "..&gt;</a>", sizeof("..&gt;</a>") - 1);

        } else {
            if (entry[i].dir && NJT_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                *b->last++ = '/';
                len++;
            }

            b->last = njt_cpymem(b->last, "</a>", sizeof("</a>") - 1);

            if (NJT_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                njt_memset(b->last, ' ', NJT_HTTP_AUTOINDEX_NAME_LEN - len);
                b->last += NJT_HTTP_AUTOINDEX_NAME_LEN - len;
            }
        }

        *b->last++ = ' ';

        njt_gmtime(entry[i].mtime + tp->gmtoff * 60 * alcf->localtime, &tm);

        b->last = njt_sprintf(b->last, "%02d-%s-%d %02d:%02d ",
                              tm.njt_tm_mday,
                              months[tm.njt_tm_mon - 1],
                              tm.njt_tm_year,
                              tm.njt_tm_hour,
                              tm.njt_tm_min);

        if (alcf->exact_size) {
            if (entry[i].dir) {
                b->last = njt_cpymem(b->last,  "                  -",
                                     sizeof("                  -") - 1);
            } else {
                b->last = njt_sprintf(b->last, "%19O", entry[i].size);
            }

        } else {
            if (entry[i].dir) {
                b->last = njt_cpymem(b->last,  "      -",
                                     sizeof("      -") - 1);

            } else {
                length = entry[i].size;

                if (length > 1024 * 1024 * 1024 - 1) {
                    size = (njt_int_t) (length / (1024 * 1024 * 1024));
                    if ((length % (1024 * 1024 * 1024))
                                                > (1024 * 1024 * 1024 / 2 - 1))
                    {
                        size++;
                    }
                    scale = 'G';

                } else if (length > 1024 * 1024 - 1) {
                    size = (njt_int_t) (length / (1024 * 1024));
                    if ((length % (1024 * 1024)) > (1024 * 1024 / 2 - 1)) {
                        size++;
                    }
                    scale = 'M';

                } else if (length > 9999) {
                    size = (njt_int_t) (length / 1024);
                    if (length % 1024 > 511) {
                        size++;
                    }
                    scale = 'K';

                } else {
                    size = (njt_int_t) length;
                    scale = '\0';
                }

                if (scale) {
                    b->last = njt_sprintf(b->last, "%6i%c", size, scale);

                } else {
                    b->last = njt_sprintf(b->last, " %6i", size);
                }
            }
        }

        *b->last++ = CR;
        *b->last++ = LF;
    }

    b->last = njt_cpymem(b->last, "</pre><hr>", sizeof("</pre><hr>") - 1);

    b->last = njt_cpymem(b->last, tail, sizeof(tail) - 1);

    return b;
}


static njt_buf_t *
njt_http_autoindex_json(njt_http_request_t *r, njt_array_t *entries,
    njt_str_t *callback)
{
    size_t                       len, entry_len;
    njt_buf_t                   *b;
    njt_uint_t                   i;
    njt_http_autoindex_entry_t  *entry;

    len = sizeof("[" CRLF CRLF "]") - 1;

    if (callback) {
        len += sizeof("/* callback */" CRLF "();") - 1 + callback->len;
    }

    entry = entries->elts;

    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = njt_escape_json(NULL, entry[i].name.data,
                                          entry[i].name.len);

        entry_len = sizeof("{  }," CRLF) - 1
                  + sizeof("\"name\":\"\"") - 1
                  + entry[i].name.len + entry[i].escape
                  + sizeof(", \"type\":\"directory\"") - 1
                  + sizeof(", \"mtime\":\"Wed, 31 Dec 1986 10:00:00 GMT\"") - 1;

        if (entry[i].file) {
            entry_len += sizeof(", \"size\":") - 1 + NJT_OFF_T_LEN;
        }

        if (len > NJT_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    if (callback) {
        b->last = njt_cpymem(b->last, "/* callback */" CRLF,
                             sizeof("/* callback */" CRLF) - 1);

        b->last = njt_cpymem(b->last, callback->data, callback->len);

        *b->last++ = '(';
    }

    *b->last++ = '[';

    for (i = 0; i < entries->nelts; i++) {
        b->last = njt_cpymem(b->last, CRLF "{ \"name\":\"",
                             sizeof(CRLF "{ \"name\":\"") - 1);

        if (entry[i].escape) {
            b->last = (u_char *) njt_escape_json(b->last, entry[i].name.data,
                                                 entry[i].name.len);
        } else {
            b->last = njt_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        b->last = njt_cpymem(b->last, "\", \"type\":\"",
                             sizeof("\", \"type\":\"") - 1);

        if (entry[i].dir) {
            b->last = njt_cpymem(b->last, "directory", sizeof("directory") - 1);

        } else if (entry[i].file) {
            b->last = njt_cpymem(b->last, "file", sizeof("file") - 1);

        } else {
            b->last = njt_cpymem(b->last, "other", sizeof("other") - 1);
        }

        b->last = njt_cpymem(b->last, "\", \"mtime\":\"",
                             sizeof("\", \"mtime\":\"") - 1);

        b->last = njt_http_time(b->last, entry[i].mtime);

        if (entry[i].file) {
            b->last = njt_cpymem(b->last, "\", \"size\":",
                                 sizeof("\", \"size\":") - 1);
            b->last = njt_sprintf(b->last, "%O", entry[i].size);

        } else {
            *b->last++ = '"';
        }

        b->last = njt_cpymem(b->last, " },", sizeof(" },") - 1);
    }

    if (i > 0) {
        b->last--;  /* strip last comma */
    }

    b->last = njt_cpymem(b->last, CRLF "]", sizeof(CRLF "]") - 1);

    if (callback) {
        *b->last++ = ')'; *b->last++ = ';';
    }

    return b;
}


static njt_int_t
njt_http_autoindex_jsonp_callback(njt_http_request_t *r, njt_str_t *callback)
{
    u_char      *p, c, ch;
    njt_uint_t   i;

    if (njt_http_arg(r, (u_char *) "callback", 8, callback) != NJT_OK) {
        callback->len = 0;
        return NJT_OK;
    }

    if (callback->len > 128) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent too long callback name: \"%V\"", callback);
        return NJT_DECLINED;
    }

    p = callback->data;

    for (i = 0; i < callback->len; i++) {
        ch = p[i];

        c = (u_char) (ch | 0x20);
        if (c >= 'a' && c <= 'z') {
            continue;
        }

        if ((ch >= '0' && ch <= '9') || ch == '_' || ch == '.') {
            continue;
        }

        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent invalid callback name: \"%V\"", callback);

        return NJT_DECLINED;
    }

    return NJT_OK;
}


static njt_buf_t *
njt_http_autoindex_xml(njt_http_request_t *r, njt_array_t *entries)
{
    size_t                          len, entry_len;
    njt_tm_t                        tm;
    njt_buf_t                      *b;
    njt_str_t                       type;
    njt_uint_t                      i;
    njt_http_autoindex_entry_t     *entry;

    static u_char  head[] = "<?xml version=\"1.0\"?>" CRLF "<list>" CRLF;
    static u_char  tail[] = "</list>" CRLF;

    len = sizeof(head) - 1 + sizeof(tail) - 1;

    entry = entries->elts;

    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = njt_escape_html(NULL, entry[i].name.data,
                                          entry[i].name.len);

        entry_len = sizeof("<directory></directory>" CRLF) - 1
                  + entry[i].name.len + entry[i].escape
                  + sizeof(" mtime=\"1986-12-31T10:00:00Z\"") - 1;

        if (entry[i].file) {
            entry_len += sizeof(" size=\"\"") - 1 + NJT_OFF_T_LEN;
        }

        if (len > NJT_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = njt_cpymem(b->last, head, sizeof(head) - 1);

    for (i = 0; i < entries->nelts; i++) {
        *b->last++ = '<';

        if (entry[i].dir) {
            njt_str_set(&type, "directory");

        } else if (entry[i].file) {
            njt_str_set(&type, "file");

        } else {
            njt_str_set(&type, "other");
        }

        b->last = njt_cpymem(b->last, type.data, type.len);

        b->last = njt_cpymem(b->last, " mtime=\"", sizeof(" mtime=\"") - 1);

        njt_gmtime(entry[i].mtime, &tm);

        b->last = njt_sprintf(b->last, "%4d-%02d-%02dT%02d:%02d:%02dZ",
                              tm.njt_tm_year, tm.njt_tm_mon,
                              tm.njt_tm_mday, tm.njt_tm_hour,
                              tm.njt_tm_min, tm.njt_tm_sec);

        if (entry[i].file) {
            b->last = njt_cpymem(b->last, "\" size=\"",
                                 sizeof("\" size=\"") - 1);
            b->last = njt_sprintf(b->last, "%O", entry[i].size);
        }

        *b->last++ = '"'; *b->last++ = '>';

        if (entry[i].escape) {
            b->last = (u_char *) njt_escape_html(b->last, entry[i].name.data,
                                                 entry[i].name.len);
        } else {
            b->last = njt_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        *b->last++ = '<'; *b->last++ = '/';

        b->last = njt_cpymem(b->last, type.data, type.len);

        *b->last++ = '>';

        *b->last++ = CR; *b->last++ = LF;
    }

    b->last = njt_cpymem(b->last, tail, sizeof(tail) - 1);

    return b;
}


static int njt_libc_cdecl
njt_http_autoindex_cmp_entries(const void *one, const void *two)
{
    njt_http_autoindex_entry_t *first = (njt_http_autoindex_entry_t *) one;
    njt_http_autoindex_entry_t *second = (njt_http_autoindex_entry_t *) two;

    if (first->dir && !second->dir) {
        /* move the directories to the start */
        return -1;
    }

    if (!first->dir && second->dir) {
        /* move the directories to the start */
        return 1;
    }

    return (int) njt_strcmp(first->name.data, second->name.data);
}


#if 0

static njt_buf_t *
njt_http_autoindex_alloc(njt_http_autoindex_ctx_t *ctx, size_t size)
{
    njt_chain_t  *cl;

    if (ctx->buf) {

        if ((size_t) (ctx->buf->end - ctx->buf->last) >= size) {
            return ctx->buf;
        }

        ctx->size += ctx->buf->last - ctx->buf->pos;
    }

    ctx->buf = njt_create_temp_buf(ctx->pool, ctx->alloc_size);
    if (ctx->buf == NULL) {
        return NULL;
    }

    cl = njt_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ctx->buf;
    cl->next = NULL;

    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    return ctx->buf;
}

#endif


static njt_int_t
njt_http_autoindex_error(njt_http_request_t *r, njt_dir_t *dir, njt_str_t *name)
{
    if (njt_close_dir(dir) == NJT_ERROR) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, njt_errno,
                      njt_close_dir_n " \"%V\" failed", name);
    }

    return r->header_sent ? NJT_ERROR : NJT_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
njt_http_autoindex_create_loc_conf(njt_conf_t *cf)
{
    njt_http_autoindex_loc_conf_t  *conf;

    conf = njt_palloc(cf->pool, sizeof(njt_http_autoindex_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NJT_CONF_UNSET;
    conf->format = NJT_CONF_UNSET_UINT;
    conf->localtime = NJT_CONF_UNSET;
    conf->exact_size = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_http_autoindex_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_autoindex_loc_conf_t *prev = parent;
    njt_http_autoindex_loc_conf_t *conf = child;

    njt_conf_merge_value(conf->enable, prev->enable, 0);
    njt_conf_merge_uint_value(conf->format, prev->format,
                              NJT_HTTP_AUTOINDEX_HTML);
    njt_conf_merge_value(conf->localtime, prev->localtime, 0);
    njt_conf_merge_value(conf->exact_size, prev->exact_size, 1);

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_autoindex_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_autoindex_handler;

    return NJT_OK;
}
