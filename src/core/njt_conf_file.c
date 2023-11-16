
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>

#define NJT_CONF_BUFFER  4096

static njt_int_t njt_conf_add_dump(njt_conf_t *cf, njt_str_t *filename);
static njt_int_t njt_conf_handler(njt_conf_t *cf, njt_int_t last);
static njt_int_t njt_conf_read_token(njt_conf_t *cf);
static njt_int_t njt_conf_element_handler(njt_pool_t *pool, njt_conf_t *cf, njt_int_t rc); // by lcm
void njt_conf_free_element(njt_pool_t *pool, njt_conf_element_t *block); // by lcm
static void njt_conf_flush_files(njt_cycle_t *cycle);


static njt_command_t  njt_conf_commands[] = {

    { njt_string("include"),
      NJT_ANY_CONF|NJT_CONF_TAKE1,
      njt_conf_include,
      0,
      0,
      NULL },

      njt_null_command
};


njt_module_t  njt_conf_module = {
    NJT_MODULE_V1,
    NULL,                                  /* module context */
    njt_conf_commands,                     /* module directives */
    NJT_CONF_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    njt_conf_flush_files,                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


/* The eight fixed arguments */

static njt_uint_t argument_number[] = {
    NJT_CONF_NOARGS,
    NJT_CONF_TAKE1,
    NJT_CONF_TAKE2,
    NJT_CONF_TAKE3,
    NJT_CONF_TAKE4,
    NJT_CONF_TAKE5,
    NJT_CONF_TAKE6,
    NJT_CONF_TAKE7
};


char *
njt_conf_param(njt_conf_t *cf)
{
    char              *rv;
    njt_str_t         *param;
    njt_buf_t          b;
    njt_conf_file_t    conf_file;

    param = &cf->cycle->conf_param;

    if (param->len == 0) {
        return NJT_CONF_OK;
    }

    njt_memzero(&conf_file, sizeof(njt_conf_file_t));

    njt_memzero(&b, sizeof(njt_buf_t));

    b.start = param->data;
    b.pos = param->data;
    b.last = param->data + param->len;
    b.end = b.last;
    b.temporary = 1;

    conf_file.file.fd = NJT_INVALID_FILE;
    conf_file.file.name.data = NULL;
    conf_file.line = 0;

    cf->conf_file = &conf_file;
    cf->conf_file->buffer = &b;

    
    rv = njt_conf_parse(cf, NULL);

    cf->conf_file = NULL;

    return rv;
}


static njt_int_t
njt_conf_add_dump(njt_conf_t *cf, njt_str_t *filename)
{
    off_t             size;
    u_char           *p;
    uint32_t          hash;
    njt_buf_t        *buf;
    njt_str_node_t   *sn;
    njt_conf_dump_t  *cd;
 //byg zyg
 #if (NJT_HTTP_DYNAMIC_LOC)
	if(cf->dynamic == 1){
           cf->conf_file->dump = NULL;
	   return NJT_OK;
	}
 #endif
    hash = njt_crc32_long(filename->data, filename->len);

    sn = njt_str_rbtree_lookup(&cf->cycle->config_dump_rbtree, filename, hash);

    if (sn) {
        cf->conf_file->dump = NULL;
        return NJT_OK;
    }

    p = njt_pstrdup(cf->cycle->pool, filename);
    if (p == NULL) {
        return NJT_ERROR;
    }

    cd = njt_array_push(&cf->cycle->config_dump);
    if (cd == NULL) {
        return NJT_ERROR;
    }

    size = njt_file_size(&cf->conf_file->file.info);

    buf = njt_create_temp_buf(cf->cycle->pool, (size_t) size);
    if (buf == NULL) {
        return NJT_ERROR;
    }

    cd->name.data = p;
    cd->name.len = filename->len;
    cd->buffer = buf;

    cf->conf_file->dump = buf;

    sn = njt_palloc(cf->temp_pool, sizeof(njt_str_node_t));
    if (sn == NULL) {
        return NJT_ERROR;
    }

    sn->node.key = hash;
    sn->str = cd->name;

    njt_rbtree_insert(&cf->cycle->config_dump_rbtree, &sn->node);

    return NJT_OK;
}


char *
njt_conf_parse(njt_conf_t *cf, njt_str_t *filename)
{
    char             *rv;
    njt_fd_t          fd;
    njt_int_t         rc;
    njt_buf_t         buf;
    njt_conf_file_t  *prev, conf_file;
    enum {
        parse_file = 0,
        parse_block,
        parse_param
    } type;

#if (NJT_SUPPRESS_WARN)
    fd = NJT_INVALID_FILE;
    prev = NULL;
#endif

    if (filename) {

        /* open configuration file */

        fd = njt_open_file(filename->data, NJT_FILE_RDONLY, NJT_FILE_OPEN, 0);

        if (fd == NJT_INVALID_FILE) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                               njt_open_file_n " \"%s\" failed",
                               filename->data);
            return NJT_CONF_ERROR;
        }

        prev = cf->conf_file;

        cf->conf_file = &conf_file;

        if (njt_fd_info(fd, &cf->conf_file->file.info) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_EMERG, cf->log, njt_errno,
                          njt_fd_info_n " \"%s\" failed", filename->data);
        }

        cf->conf_file->buffer = &buf;

        buf.start = njt_alloc(NJT_CONF_BUFFER, cf->log);
        if (buf.start == NULL) {
            goto failed;
        }
        //by cheng xu
#if (NJT_DEBUG)
        njt_log_debug0(NJT_LOG_DEBUG_CORE, cf->log, 0,"alloc cf->conf_file->buffer ");
#endif
        //end
        buf.pos = buf.start;
        buf.last = buf.start;
        buf.end = buf.last + NJT_CONF_BUFFER;
        buf.temporary = 1;

        cf->conf_file->file.fd = fd;
        cf->conf_file->file.name.len = filename->len;
        cf->conf_file->file.name.data = filename->data;
        cf->conf_file->file.offset = 0;
        cf->conf_file->file.log = cf->log;
        cf->conf_file->line = 1;

        type = parse_file;

        if (njt_dump_config
#if (NJT_DEBUG)
            || 1
#endif
           )
        {
            if (njt_conf_add_dump(cf, filename) != NJT_OK) {
                goto failed;
            }

        } else {
            cf->conf_file->dump = NULL;
        }

    } else if (cf->conf_file->file.fd != NJT_INVALID_FILE) {

        type = parse_block;

    } else {
        type = parse_param;
    }

 
    for ( ;; ) {
        rc = njt_conf_read_token(cf);

        /*
         * njt_conf_read_token() may return
         *
         *    NJT_ERROR             there is error
         *    NJT_OK                the token terminated by ";" was found
         *    NJT_CONF_BLOCK_START  the token terminated by "{" was found
         *    NJT_CONF_BLOCK_DONE   the "}" was found
         *    NJT_CONF_FILE_DONE    the configuration file is done
         */

        if (rc == NJT_ERROR) {
            goto done;
        }

        // add by lcm
        if (njt_process == NJT_PROCESS_SINGLE || 1) { // 需要修改, 先所有进程都作一下更新
            if (njt_conf_element_handler(cf->pool, cf, rc) != NJT_OK) {
                printf("error occured \n");
            }
        }
        // end of add


        if (rc == NJT_CONF_BLOCK_DONE) {

            if (type != parse_block) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "unexpected \"}\"");
                goto failed;
            }

            goto done;
        }

        if (rc == NJT_CONF_FILE_DONE) {

            if (type == parse_block) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "unexpected end of file, expecting \"}\"");
                goto failed;
            }

            goto done;
        }

        if (rc == NJT_CONF_BLOCK_START) {

            if (type == parse_param) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "block directives are not supported "
                                   "in -g option");
                goto failed;
            }
        }

        /* rc == NJT_OK || rc == NJT_CONF_BLOCK_START */

        if (cf->handler) {

            /*
             * the custom handler, i.e., that is used in the http's
             * "types { ... }" directive
             */

            if (rc == NJT_CONF_BLOCK_START) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "unexpected \"{\"");
                goto failed;
            }

            rv = (*cf->handler)(cf, NULL, cf->handler_conf);
            if (rv == NJT_CONF_OK) {
                continue;
            }

            if (rv == NJT_CONF_ERROR) {
                goto failed;
            }

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%s", rv);

            goto failed;
        }


        rc = njt_conf_handler(cf, rc);

        if (rc == NJT_ERROR) {
            goto failed;
        }
    }

failed:

    rc = NJT_ERROR;

done:

    if (filename) {
        if (cf->conf_file->buffer->start) {
            njt_free(cf->conf_file->buffer->start);
        }

        if (njt_close_file(fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                          njt_close_file_n " %s failed",
                          filename->data);
            rc = NJT_ERROR;
        }

        cf->conf_file = prev;
    }

    if (rc == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

static njt_int_t
njt_conf_cmd_set_args(njt_pool_t *pool, njt_conf_t *cf, njt_conf_cmd_t *ccmd){
    njt_uint_t      i, j;
    njt_uint_t      need_escape, re_location;
    njt_str_t      *arg, *value;
    njt_str_t       index;
    size_t          vlen;
    char           *cur, *dst;
    njt_array_t    *pos, *tmp;

    pos = njt_array_push(ccmd->value);
    tmp = njt_array_create(pool, 1, sizeof(njt_str_t));
    if (pos == NULL || tmp == NULL) {
        return NJT_ERROR;
    }
    njt_memcpy(pos, tmp, sizeof(njt_array_t));

    if (cf->args->nelts == 1) {
        value = njt_array_push(pos);
        value->data = njt_palloc(pool, 1);
        if (value->data == NULL) {
            return NJT_ERROR;
        }
        njt_str_set(value, ""); // value->len = 0;
        return NJT_OK;
    }

    arg = cf->args->elts;
    re_location = arg->len == 8 && njt_strncmp(arg->data, "location", 8) == 0 && cf->args->nelts == 3;
    if (re_location) {
        vlen =0;
        for(i = 1; i < cf->args->nelts; i++){
            arg = &((njt_str_t*)cf->args->elts)[i];
            vlen += arg->len;
        }
        index.data = njt_pcalloc(pool, vlen+1);
        if (index.data == NULL){
            return NJT_ERROR;
        }
        index.len = 0;
        for(i = 1; i < cf->args->nelts; i++){
            arg = &((njt_str_t*)cf->args->elts)[i];
            njt_memcpy(index.data + index.len, arg->data, arg->len);
            index.len += arg->len;
        }
        index.len = vlen;
        arg = &index;
    }


    for (i = 1; i < cf->args->nelts; i++) {
        value = njt_array_push(pos);
        if (value == NULL) {
            return NJT_ERROR;
        }
        if (!re_location) { // re_location arg = &index
            arg = &((njt_str_t*)cf->args->elts)[i];
        }
        need_escape = 0;
        for (j = 0; j < arg->len; j++) {
            switch ((char)arg->data[j]) {
                case '\\': 
                // case '/':  need_convert = true; break;
                case '"':  
                case '\b':  
                case '\f':  
                case '\n':  
                case '\r':  
                case '\t':  need_escape ++; break;
                default:
                     break;
            }
        }

        vlen = need_escape + arg->len;
        value->data = njt_palloc(cf->cycle->pool, vlen);
        if (value->data == NULL) {
            return NJT_ERROR;
        }

        value->len = vlen;
        dst = (char*)value->data;
        cur = (char*)arg->data;

        if (!need_escape) {
            for (j = 0; j < arg->len; j++, cur++) {
                *dst++ = *cur;
            }
        } else {
            for (j = 0; j < arg->len; j++, cur++) {
                switch (*cur) {
                    case '"':  *dst++ = '\\'; *dst++ = '"'; break;
                    case '\\': *dst++ = '\\'; *dst++ = '\\'; break;
                    // case '/':  *dst++ = '\\'; *dst++ = '/'; out->len++; break;
                    case '\b': *dst++ = '\\'; *dst++ = 'b'; break;
                    case '\f': *dst++ = '\\'; *dst++ = 'f'; break;
                    case '\n': *dst++ = '\\'; *dst++ = 'n'; break;
                    case '\r': *dst++ = '\\'; *dst++ = 'r'; break;
                    case '\t': *dst++ = '\\'; *dst++ = 't'; break;
                    default:
                        *dst++ = *cur;
                }
            }
        }
        if (re_location) {
            break;
        }
    }



    return NJT_OK;
}

// 如果数据已经转义过了，这里是不是要加个标志
static njt_int_t
njt_conf_cmd_set_value(njt_pool_t *pool, njt_conf_cmd_t *cmd, njt_array_t *cf){
    njt_uint_t      i, j;
    njt_uint_t      need_escape;
    njt_str_t      *arg, *value;
    size_t          vlen;
    char           *cur, *dst;
    njt_array_t    *pos, *tmp;

    pos = njt_array_push(cmd->value);
    tmp = njt_array_create(pool, 1, sizeof(njt_str_t));
    if (pos == NULL || tmp == NULL) {
        return NJT_ERROR;
    }
    njt_memcpy(pos, tmp, sizeof(njt_array_t));

    if (cf->nelts == 1) {
        value = njt_array_push(pos);
        value->data = njt_palloc(pool, 1);
        if (value->data == NULL) {
            return NJT_ERROR;
        }
        njt_str_set(value, ""); // value->len = 0;
        return NJT_OK;
    }


    for (i = 1; i < cf->nelts; i++) { 
        value = njt_array_push(pos);
        if (value == NULL) {
            return NJT_ERROR;
        }
        arg = &((njt_str_t*)cf->elts)[i];
        need_escape = 0;
        for (j = 0; j < arg->len; j++) {
            switch ((char)arg->data[j]) {
                case '\\': 
                // case '/':  need_convert = true; break;
                case '"':  
                case '\b':  
                case '\f':  
                case '\n':  
                case '\r':  
                case '\t':  need_escape ++; break;
                default:
                     break;
            }
        }

        vlen = need_escape + arg->len;
        value->data = njt_palloc(pool, vlen);
        if (value->data == NULL) {
            return NJT_ERROR;
        }

        value->len = vlen;
        dst = (char*)value->data;
        cur = (char*)arg->data;

        if (!need_escape) {
            for (j = 0; j < arg->len; j++, cur++) {
                *dst++ = *cur;
            }
        } else {
            for (j = 0; j < arg->len; j++, cur++) {
                switch (*cur) {
                    case '"':  *dst++ = '\\'; *dst++ = '"'; break;
                    case '\\': *dst++ = '\\'; *dst++ = '\\'; break;
                    // case '/':  *dst++ = '\\'; *dst++ = '/'; out->len++; break;
                    case '\b': *dst++ = '\\'; *dst++ = 'b'; break;
                    case '\f': *dst++ = '\\'; *dst++ = 'f'; break;
                    case '\n': *dst++ = '\\'; *dst++ = 'n'; break;
                    case '\r': *dst++ = '\\'; *dst++ = 'r'; break;
                    case '\t': *dst++ = '\\'; *dst++ = 't'; break;
                    default:
                        *dst++ = *cur;
                }
            }
        }
    }

    return NJT_OK;
}


void njt_conf_get_json_length(njt_conf_element_t *root, size_t *length, njt_uint_t is_root) {
    njt_uint_t               i, j, k;
    njt_conf_cmd_t          *cmd;
    njt_array_t             *values;
    njt_str_t               *arg;
    njt_conf_block_t        *blocks;
    njt_conf_element_t      *block;
    njt_uint_t               svr_or_loc, sname, listen; 

    *length += 1;

    if(root == NULL) {
        return;
    }

    if (root->block_name != NULL) {
        *length += 7; // "_key":  "block_name",
        cmd = root->block_name;
        if (cmd->value->nelts == 1) {
            // "key": "value",
            values = cmd->value->elts;
            if (values->nelts == 1) {
                // all as string now, change to boolean or number later
                arg = (njt_str_t*)values->elts;// "key": "value",
                *length += arg->len + 2;
            } else {
                *length += 1; 
                for (k = 0; k < values->nelts; k++) {
                    arg = &((njt_str_t*)values->elts)[k];
                    *length += arg->len + 3;
                }
            }
        }
        *length += 1; 
    }
      

    if (root->cmds) {
        for (i = 0; i < root->cmds->nelts; i++) {
            cmd = &((njt_conf_cmd_t *)root->cmds->elts)[i];
            *length += cmd->key.len + 3;
            listen = (cmd->key.len == 6 && njt_strncmp(cmd->key.data, "listen", 6) == 0);
            sname = (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server_name", 11) == 0);
            if (cmd->value->nelts == 1 && !listen) {
                // "key": "value",
                values = cmd->value->elts;
                if (values->nelts == 1 && !sname) {
                    // all as string now, change to boolean or number later
                    arg = (njt_str_t *)values->elts; // "key": "value",
                    *length += arg->len + 2;
                } else {
                    *length += 1;
                    for (k = 0; k < values->nelts; k++) {
                        arg = &((njt_str_t *)values->elts)[k];
                        *length += arg->len + 3;
                    }
                    if (k == 0) {
                        *length += 1;
                    }
                }
            } else {
                *length += 1;
                for (j = 0; j < cmd->value->nelts; j++) {
                    *length += 1;
                    values = &((njt_array_t *)cmd->value->elts)[j];
                    for (k = 0; k < values->nelts; k++) {
                        arg = &((njt_str_t *)values->elts)[k];
                        *length += arg->len + 3;
                    }
                    if (k == 0) {
                        *length += 1;
                    }
                    *length += 1;
                }
                if (j == 0) {
                    *length += 1;
                }
            }
            *length += 1;
        }
    }

    if (root->blocks == NULL) {
        return;
    }

    for (i = 0; i < root->blocks->nelts; i++) {
        blocks = &((njt_conf_block_t*)root->blocks->elts)[i];
        *length += blocks->key.len + 3;
        svr_or_loc = (blocks->key.len == 6 && njt_strncmp(blocks->key.data, "server", 6) == 0)
                     || (blocks->key.len == 8 && njt_strncmp(blocks->key.data, "location", 8) == 0);
        if (blocks->value->nelts == 1 && !svr_or_loc) {
            block = blocks->value->elts; // http : {}
            njt_conf_get_json_length(block, length, 0);
        } else { // locaction [{location1}, {location2}, ...]
            *length += 1;
            for (j = 0; j < blocks->value->nelts; j++) {
                block = &((njt_conf_element_t*)blocks->value->elts)[j];
                njt_conf_get_json_length(block, length, 0);
                *length += 1;
            }
        }
        *length += 1;
    }
}

// 如果能保证sub_name的名称是唯一的，也可以进行递归查找
njt_conf_element_t*
njt_conf_get_http_block(njt_pool_t *dyn_pool) {
    njt_str_t           http;
    njt_conf_element_t *ret;

    http.data = njt_palloc(dyn_pool, 4);
    if (http.data == NULL) {
        return NULL;
    }

    njt_str_set(&http, "http");
    ret = njt_conf_get_block(njt_conf_root_ptr, &http, NULL);
    njt_pfree(dyn_pool, http.data);

    return ret;
}

njt_conf_element_t*
njt_conf_get_simple_location_block(njt_pool_t *dyn_pool, njt_conf_element_t *cur, njt_str_t *name) {
    njt_str_t           loc, *pos;
    njt_array_t        *sub_name;
    njt_conf_element_t *ret;

    loc.data = njt_palloc(dyn_pool, 8);
    if (loc.data == NULL) {
        return NULL;
    }

    sub_name = njt_array_create(dyn_pool, 1, sizeof(njt_str_t));
    if (sub_name == NULL) {
        njt_pfree(dyn_pool, loc.data);
        return NULL;
    }

    pos = njt_array_push(sub_name);
    njt_memcpy(pos, name, sizeof(njt_str_t));

    njt_str_set(&loc, "location");
    ret = njt_conf_get_block(njt_conf_cur_ptr, &loc, sub_name);
    njt_array_destroy(sub_name);
    njt_pfree(dyn_pool, loc.data);


    return ret;
}

njt_conf_element_t* 
njt_conf_get_block( njt_conf_element_t *cur, 
    njt_str_t *key, njt_array_t *sub_names)
 {
    njt_uint_t           i, j, k;
    njt_uint_t           same;
    njt_str_t           *arg, *sub_name;
    njt_array_t         *args;
    njt_conf_cmd_t      *cmd;
    njt_conf_block_t    *blocks;
    njt_conf_element_t  *block, *ret;

    ret = NULL;
    if (cur->blocks == NULL || cur->blocks->nelts == 0) {
        return ret;
    }

    for (i = 0; i < cur->blocks->nelts; i++) {
        blocks = &((njt_conf_block_t*) cur->blocks->elts)[i];
        if (key->len == blocks->key.len 
            && njt_strncmp(key->data, blocks->key.data, key->len) == 0) 
        {
            if (sub_names == NULL) {
                ret = blocks->value->elts; // MUST block->value->nelts == 1
                return ret;
            }

            for (j = 0; j < blocks->value->nelts; j++) {
                block = &((njt_conf_element_t*)blocks->value->elts)[j];
                cmd = block->block_name;
                if (cmd == NULL) { // IN CASE
                    if (sub_names->nelts == 1){
                         sub_name = (njt_str_t *)sub_names->elts;
                         if (sub_name->len == 0) {
                            return block;
                         }
                    }
                } 
                if (cmd != NULL) {
                    // 需要要cmd 和 sub_names 完全一样才算匹配
                    args = (njt_array_t*)cmd->value->elts; // _key must be one line
                    // if (sub_names->nelts == 1){
                    //     sub_name = (njt_str_t *)sub_names->elts;
                    //     for (k = 0; k < args->nelts; k++) {
                    //         arg = &((njt_str_t*)args->elts)[k];
                    //         if (arg->len == sub_name->len 
                    //             && njt_strncmp(arg->data, 
                    //                         sub_name->data, arg->len) == 0)
                    //         {
                    //             return block;
                    //         }
                    //     }

                    // } else {
                    same = 0;
                    if (args->nelts == sub_names->nelts){
                        for (k = 0; k < args->nelts; k++) {
                            arg = &((njt_str_t*)args->elts)[k];
                            sub_name = &((njt_str_t*)sub_names->elts)[k];
                            if (arg->len == sub_name->len 
                                && njt_strncmp(arg->data, 
                                            sub_name->data, arg->len) == 0)
                            {
                                same++;
                            } else {
                                break;
                            }
                        }
                        if (same == args->nelts) {
                            return block;
                        }
                    }
                    // }
                }
            }

        }
    }
    return NULL;
};

njt_conf_element_t* 
njt_conf_get_server_block(njt_conf_element_t *cur,
    njt_str_t *listen, njt_str_t *server_name)
{
    u_char              *p, *port, *listen_port;
    njt_uint_t           i, j, ii, jj, kk;
    njt_uint_t           pos;
    njt_uint_t           found_listen, found_server, addr_match, port_match;
    njt_uint_t           listen_checked, server_name_checked;
    njt_uint_t           localhost, listen_localhost;
    njt_int_t            tmp_port, tmp_listen_port;
    njt_str_t           *arg;
    njt_array_t         *values, *cmds;
    njt_conf_cmd_t      *cmd;
    njt_conf_block_t    *blocks;
    njt_conf_element_t  *block, *ret;

    ret = NULL;
    
    if (cur->blocks == NULL || cur->blocks->nelts == 0) {
        return ret;
    }

    for (i = 0; i < cur->blocks->nelts; i++) {
        blocks = &((njt_conf_block_t*) cur->blocks->elts)[i];
        if (blocks->key.len == 6 
            && njt_strncmp(blocks->key.data, "server", 6) == 0) 
        {
            for (j = 0; j < blocks->value->nelts; j++) {

                block = &((njt_conf_element_t*)blocks->value->elts)[j];
                cmds = block->cmds;

                if (cmds != NULL) {
                    found_listen = 0;
                    found_server = 0;
                    listen_checked = 0;
                    server_name_checked = 0;
                    for (ii = 0; ii < cmds->nelts; ii++) {
                        cmd = &((njt_conf_cmd_t *)(cmds->elts))[ii];
                        // "listen"           or       "server_name"
                        if (cmd->key.len != 6 && cmd->key.len != 11) {
                            continue;
                        }
                        if (cmd->key.len == 6 && listen != NULL && !listen_checked) {
                            // 这里之前用njt_strcmp出过错误，有时ccmd->key_data的len之后不是\0
                            if (njt_memcmp(cmd->key.data, "listen", 6) != 0)
                            {
                                continue;
                            } 
                            listen_checked = 1;
                            for (jj = 0; jj < cmd->value->nelts; jj++) {
                                addr_match = 0;
                                port_match = 0;
                                values = &((njt_array_t*)cmd->value->elts)[jj];
                                if (values->nelts == 0) { // 是否需要
                                    continue;
                                }
                                // parse url???
                                arg = (njt_str_t*)values->elts;// 第一个元素,
                                // 先不考虑unix domain
                                // if (len >= 5 && njt_strncasecmp(p, (u_char *) "unix:", 5) == 0) 
                                p = arg->data;
                                if (arg->len) {
                                    if (p[0] == '[') { // ipv6
                                        // ipv6 目前仅实行字符串完全比较
                                        if (arg->len == listen->len &&
                                            njt_memcmp(p, listen->data,
                                                       arg->len) == 0)
                                        {
                                            found_listen = 1;
                                        }
                                    } else { // ipv4
                                        // 目前只考虑 address:port情况 或者 address 或者 port
                                        // njt_parse_inet_url里有更复杂的处理
                                        // 比较port 如果没有，默认80 (暂不考虑8000)
                                        port = njt_strlchr(p, p + arg->len, ':');
                                        listen_port = njt_strlchr(listen->data, listen->data + listen->len, ':');
                                        if (port && listen_port) {
                                            if ( (p + arg->len - port) == (listen->data + listen->len - listen_port)
                                                && njt_memcmp(port+1, listen_port+1, p + arg->len - port) == 0)
                                            {
                                                port_match = 1;
                                            }
                                        } else if (port) { // listen_port 没有
                                            tmp_port = njt_atoi(p+1, p + arg->len - port - 1);
                                            tmp_listen_port = njt_atoi(listen->data, listen->len);
                                            if (tmp_port == tmp_listen_port) {
                                                port_match = 1;
                                            } else if (tmp_listen_port == NJT_ERROR && tmp_port == 80) {
                                                port_match = 1;
                                            }
                                        } else if (listen_port) {
                                            tmp_port = njt_atoi(arg->data, arg->len);
                                            tmp_listen_port = njt_atoi(listen_port+1, listen->data + listen->len - listen_port - 1);
                                            if (tmp_port == tmp_listen_port) {
                                                port_match = 1;
                                            } else if (tmp_port == NJT_ERROR && tmp_listen_port == 80) {
                                                port_match = 1;
                                            }
                                        } else { // 都是 port形式， 直接比较atoi(), 合法性不在这里检验
                                            port_match = njt_atoi(arg->data, arg->len) == njt_atoi(listen->data, listen->len);
                                        }


                                        tmp_port = njt_atoi(arg->data, arg->len);
                                        tmp_listen_port = njt_atoi(listen->data, listen->len);
                                        localhost = 0;
                                        listen_localhost = 0;
                                        // 80 表示地址是0.0.0.0
                                        if ( tmp_port != NJT_ERROR || tmp_listen_port != NJT_ERROR 
                                             || (arg->len >= 7 && njt_memcmp(arg->data, "0.0.0.0", 7)) == 0 
                                             || (listen->len >= 7 && njt_memcmp(listen->data, "0.0.0.0", 7)) == 0) 
                                        {
                                            addr_match = 1;
                                        } else { // 127.0.0.1 == localhost
                                            if (arg->len >= 9 && (njt_memcmp(p, "localhost", 9) == 0 
                                                                || njt_memcmp(p, "127.0.0.1", 9) == 0)) {
                                                localhost = 1;
                                            } 
                                            if (listen->len >= 9 && (njt_memcmp(listen->data, "localhost", 9) == 0 
                                                                   || njt_memcmp(listen->data, "127.0.0.1", 9) == 0)) {
                                                listen_checked = 1;
                                            } 
                                            if (localhost == 0 && listen_localhost == 0) {
                                                if (port) {
                                                    if (((listen_port && port - p == listen_port - listen->data) || (size_t)(port - p) == listen->len) 
                                                        && njt_memcmp(p, listen->data, port - p) == 0)
                                                    {
                                                        addr_match = 1;
                                                    }
                                                } else {
                                                    if (((listen_port && arg->len == (size_t)(listen_port - listen->data)) || arg->len == listen->len) 
                                                        && njt_memcmp(p, listen->data, arg->len) == 0)
                                                    {
                                                        addr_match = 1;
                                                    }

                                                }
                                            } 
                                        }
                                    }
                                }

                                if (addr_match && port_match) {
                                    found_listen = 1;
                                    break;
                                }
                            } // for jj
                        }
                        if (cmd->key.len == 11 && server_name != NULL && !server_name_checked) {
                            // 这里之前用njt_strcmp出过错误，有时ccmd->key_data的len之后不是\0
                            if (njt_memcmp(cmd->key.data, "server_name", 11) != 0)
                            {
                                continue;
                            } 
                            server_name_checked = 1;
                            for (jj = 0; jj < cmd->value->nelts; jj++) {
                                values = &((njt_array_t*)cmd->value->elts)[jj];
                                if (values->nelts == 0) { // 是否需要
                                    continue;
                                }
                                for (kk = 0; kk < values->nelts; kk++) {
                                    arg = &((njt_str_t*)values->elts)[kk];// 每一个元素,
                                    if (arg->len == server_name->len) {
                                        // 不区分大小写
                                        found_server = 1;
                                        for (pos = 0; pos < arg->len; pos++) {
                                            if (njt_tolower(arg->data[pos]) != njt_tolower(server_name->data[pos])) {
                                                found_server = 0;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if (found_server) break;
                            } // for jj
                        }
                        if (found_listen && found_server) {
                            return block;
                        }
                        // server_name 没设置相当于 ""，或者只有listen一个条件
                        if (found_listen && ((!server_name_checked && server_name->len == 0) || server_name == NULL)) {
                            return block;
                        }
                        if (listen_checked && server_name_checked) break;
                    } // for ii

                }
            }

        }
    }
    return NULL;
};


njt_conf_cmd_t*
njt_conf_get_cmd_conf(njt_conf_element_t *block, njt_str_t *key) {
    njt_uint_t      i;
    njt_conf_cmd_t *cmd;

    for (i=0; i<block->cmds->nelts; i++) {
        cmd = &((njt_conf_cmd_t*)block->cmds->elts)[i];
        if (cmd->key.len == key->len
            && njt_strncmp(cmd->key.data, key->data, key->len) == 0)
        {
            return cmd;
        }

    }
    return NULL;

};

void njt_conf_free_cmd(njt_pool_t *pool, njt_conf_cmd_t *cmd) {
    njt_uint_t      i, j;
    njt_array_t    *values;
    njt_str_t      *arg;

    if (cmd->key.data) {
        njt_pfree(pool, cmd->key.data);
    }

    if (cmd->value == NULL) {
        return;
    }

    for (i = 0; i < cmd->value->nelts; i++) {
        values = &((njt_array_t*)cmd->value->elts)[i];
        for (j = 0; j < values->nelts; j++) {
            arg = &((njt_str_t*)values->elts)[j];
            if (arg->data) {
                njt_pfree(pool, arg);
            }
            
        }
        njt_pfree(pool, values->elts);
    }
    njt_pfree(pool, cmd->value->elts);
}

void njt_conf_free_block(njt_pool_t *pool, njt_conf_block_t *block) {
    njt_uint_t               i; 
    njt_conf_element_t      *sub_block;


    if (block->key.data) {
        njt_pfree(pool, block->key.data);
    }

    if (block->value == NULL) {
        return;
    }

    for (i = 0; i < block->value->nelts; i++) {
        sub_block = &((njt_conf_element_t *)block->value->elts)[i];
        njt_conf_free_element(pool, sub_block);
    }
    njt_pfree(pool, block->value->elts);
}

void njt_conf_free_element(njt_pool_t *pool, njt_conf_element_t *block) {
    njt_uint_t          i;
    njt_conf_cmd_t     *cmd;
    njt_conf_block_t   *sub_block;

    if (block->block_name) {
        njt_conf_free_cmd(pool, block->block_name);
        njt_pfree(pool, block->block_name);
    }

    if (block->cmds) {
        for (i = 0; i < block->cmds->nelts; i++) {
            cmd = &((njt_conf_cmd_t*)block->cmds->elts)[i];
            njt_conf_free_cmd(pool, cmd);
        }
        njt_pfree(pool, block->cmds->elts);
    }

    if (block->blocks) {
        for (i = 0; i < block->blocks->nelts; i++) {
            sub_block = &((njt_conf_block_t *)block->blocks->elts)[i];
            njt_conf_free_block(pool, sub_block);
        }
        njt_pfree(pool, block->blocks->elts);
    }
}

njt_int_t njt_conf_delete_block(njt_pool_t *pool, njt_conf_element_t *block) {
    njt_uint_t          i, j, k;
    njt_conf_block_t   *blocks;
    njt_conf_element_t *parent, *cur, *next;

    if (block->parent != NULL) {
        parent = block->parent;
        for (i = 0; i < parent->blocks->nelts; i++) {
            blocks = &((njt_conf_block_t*)parent->blocks->elts)[i];
            for (j = 0; j < blocks->value->nelts; j++) {
                cur = &((njt_conf_element_t*)blocks->value->elts)[j];
                if (cur == block) {
                    //TODO 释放内存
                    njt_conf_free_element(pool, block);

                    for (k = j+1; k < blocks->value->nelts; k++) {
                        next = &((njt_conf_element_t*)blocks->value->elts)[k];
                        njt_memcpy(cur, next, sizeof(njt_conf_element_t));
                        cur = next;
                    }

                    njt_memset(cur, 0, sizeof(njt_conf_element_t)); // 是否必要，我看对cf的处理里面只是修改了 nelts，
                    blocks->value->nelts -= 1;
                    return NJT_OK;
                }

            }
        }

    }
    return NJT_ERROR;
}

njt_conf_element_t* 
njt_conf_create_block(njt_pool_t *pool, njt_array_t *names) 
{
    njt_uint_t           i;
    njt_str_t           *value, *name;
    njt_array_t         *pos, *tmp;
    njt_conf_element_t  *block;

    block = njt_pcalloc(pool, sizeof(njt_conf_element_t));
    if (block == NULL) {
        return NULL;
    }

    block->block_name = njt_palloc(pool, sizeof(njt_conf_cmd_t));
    if (block->block_name == NULL) {
        return NULL;
    }

    block->block_name->value = njt_array_create(pool, 1, sizeof(njt_array_t));
    if (block->block_name->value == NULL) {
        return NULL;
    }

    pos = njt_array_push(block->block_name->value);
    tmp = njt_array_create(pool, names->nelts, sizeof(njt_str_t));
    if (pos == NULL || tmp == NULL) {
        return NULL;
    }
    njt_memcpy(pos, tmp, sizeof(njt_array_t));

    for (i = 0; i < names->nelts; i++) {
        value = njt_array_push(pos);
        name = &((njt_str_t *)names->elts)[i];
        value->data = njt_palloc(pool, name->len);
        if (value->data == NULL) {
            return NULL;
        }
        njt_memcpy(value->data, name->data, name->len); 
        value->len = name->len;
    }

    return block;
}

njt_int_t
njt_conf_add_cmd(njt_pool_t *pool, njt_conf_element_t *block, njt_array_t *cf) {
    njt_uint_t       i, found;
    njt_str_t       *name;
    njt_conf_cmd_t  *cmd;

    if (!block->cmds) {
        block->cmds = njt_array_create(pool, 1, sizeof(njt_conf_cmd_t));
        if (!block->cmds) {
            return NJT_ERROR;
        }
    }

    name = cf->elts;
    found = 0;
    for (i = 0; i < block->cmds->nelts; i++) {
        cmd = &((njt_conf_cmd_t *)(block->cmds->elts))[i];
        if (cmd->key.len != name->len) {
            continue;
        }

        // 这里之前用njt_strcmp出过错误，有时ccmd->key_data的len之后不是\0
        if (njt_memcmp(name->data, cmd->key.data, name->len) != 0) {
            continue;
        }

        found = 1;
        break;
    }

    if (!found) {
        cmd = njt_array_push(block->cmds);
        if (cmd == NULL) {
            return NJT_ERROR;
        }
        cmd->key.data = njt_palloc(pool, name->len);
        if (cmd->key.data == NULL) {
            return NJT_ERROR;
        }
        cmd->key.len = name->len;
        njt_memcpy(cmd->key.data, name->data, name->len);
        cmd->value = njt_array_create(pool, 1, sizeof(njt_array_t));
    }
    
    return njt_conf_cmd_set_value(pool, cmd, cf);
}

// 将当前内容加到cmd的最后，如果已经有当前内容，提取出来再加到后面
// 例如 location / {listen 8080; listen 127.0.0.1:8888;}
// 在 readd listen 8080; 后
// 变为 location / {listen 127.0.0.1:8888; listen 8080;}
njt_int_t
njt_conf_cmd_hit_item(njt_pool_t *pool, njt_conf_element_t *block, njt_array_t *cf) {
    njt_uint_t       i, j, found, match;
    njt_str_t       *name, *arg;
    njt_array_t     *values, tmp;
    njt_conf_cmd_t  *cmd;


    if (!block->cmds) {
        block->cmds = njt_array_create(pool, 1, sizeof(njt_conf_cmd_t));
        if (!block->cmds) {
            return NJT_ERROR;
        }
    }
    
    name = cf->elts;
    found = 0;
    for (i = 0; i < block->cmds->nelts; i++) {
        cmd = &((njt_conf_cmd_t *)(block->cmds->elts))[i];
        if (cmd->key.len != name->len) {
            continue;
        }

        // 这里之前用njt_strcmp出过错误，有时ccmd->key_data的len之后不是\0
        if (njt_memcmp(name->data, cmd->key.data, name->len) != 0) {
            continue;
        }

        found = 1;
        break;
    }

    if (!found) {
        cmd = njt_array_push(block->cmds);
        if (cmd == NULL) {
            return NJT_ERROR;
        }
        cmd->key.data = njt_palloc(pool, name->len);
        if (cmd->key.data == NULL) {
            return NJT_ERROR;
        }
        cmd->key.len = name->len;
        njt_memcpy(cmd->key.data, name->data, name->len);
        cmd->value = njt_array_create(pool, 1, sizeof(njt_array_t));
        return njt_conf_cmd_set_value(pool, cmd, cf);
    }

    for (i = 0; i < cmd->value->nelts; i++) {

        values = &((njt_array_t *)cmd->value->elts)[i];
        if (values->nelts != cf->nelts - 1) { // 必须是全量匹配
            continue;
        } 
        
        match = 1;
        for (j = 0; j < values->nelts; j++) {
            arg = &((njt_str_t*)values->elts)[j];
            name = &((njt_str_t*)cf->elts)[j+1]; // cf->elts[0] = cmd.name
            if (arg->len != name->len || njt_strncmp(arg->data, name->data, arg->len) != 0) {
           
                match = 0;
                break;
            }
        }
        if (match) { // move to tail 
            tmp = *values;
            for (j = i+1; j < cmd->value->nelts; j++) {
                njt_memcpy(&((njt_array_t *)cmd->value->elts)[j-1], &((njt_array_t *)cmd->value->elts)[j], sizeof(njt_array_t));   
            }
            njt_memcpy(&((njt_array_t *)cmd->value->elts)[j], &tmp, sizeof(njt_array_t));   
            return NJT_OK;
        }
    } 

    // match == 0
    return njt_conf_cmd_set_value(pool, cmd, cf);

}

// 只删除完全对应的那一条，其他的保存不变, 目前只做全量匹配
// 例如 location / {listen 8080; listen 127.0.0.1:8888;}
// 在 删除 listen 8080; 后
// 变为 location / {listen 127.0.0.1:8888;}
njt_int_t
njt_conf_cmd_del_item(njt_pool_t *pool, njt_conf_element_t *block, njt_array_t *cf) {
    njt_uint_t       i, j, found, match;
    njt_str_t       *name, *arg;
    njt_array_t     *values, tmp;
    njt_conf_cmd_t  *cmd;

    if (!block->cmds) {
        return NJT_OK;
    }

    name = cf->elts;
    found = 0;
    for (i = 0; i < block->cmds->nelts; i++) {
        cmd = &((njt_conf_cmd_t *)(block->cmds->elts))[i];
        if (cmd->key.len != name->len) {
            continue;
        }

        // 这里之前用njt_strcmp出过错误，有时ccmd->key_data的len之后不是\0
        if (njt_memcmp(name->data, cmd->key.data, name->len) != 0) {
            continue;
        }

        found = 1;
        break;
    }

    if (!found) {
        return NJT_OK;
    }

    for (i = 0; i < cmd->value->nelts; i++) {

        values = &((njt_array_t *)cmd->value->elts)[i];
        if (values->nelts != cf->nelts - 1) { // 必须是全量匹配
            continue;
        } 
        
        match = 1;
        for (j = 0; j < values->nelts; j++) {
            arg = &((njt_str_t*)values->elts)[j];
            name = &((njt_str_t*)cf->elts)[j+1]; // cf->elts[0] = cmd.name
            if (arg->len != name->len || njt_strncmp(arg->data, name->data, arg->len) != 0) {
           
                match = 0;
                break;
            }
        }
        if (match) {
            tmp = *values;
            for (j = i+1; j < cmd->value->nelts; j++) {
                njt_memcpy(&((njt_array_t *)cmd->value->elts)[j-1], &((njt_array_t *)cmd->value->elts)[j], sizeof(njt_array_t));   
            }
 
            // free tmp->elts[j]->data
            for (j = 0; j < tmp.nelts; j++) {
                arg = &((njt_str_t*)values->elts)[j];
                if (arg->data != NULL) {
                    njt_pfree(pool, arg->data);
                }
            }
            njt_memset(tmp.elts, 0, tmp.nalloc * sizeof(njt_str_t));
            tmp.nelts = 0;
            njt_memcpy(&((njt_array_t *)cmd->value->elts)[cmd->value->nelts - 1], &tmp, sizeof(njt_array_t));   
            cmd->value->nelts--;
            break;
        }
    } 

    return NJT_OK;
}

njt_int_t
njt_conf_check_svrname_listen(njt_pool_t *pool, njt_conf_element_t *root) {
    njt_conf_element_t *http, *svr;
    njt_conf_block_t   *blocks;
    njt_conf_cmd_t     *listen;
    njt_array_t        *cf, *args;
    njt_str_t           sname, slisten, slocalhost, *arg, *new_arg;
    njt_uint_t          i, j, k, l, is_local;
    u_char             *port;
    njt_pool_t         *dyn_pool;

    cf = NULL;
    dyn_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    sname.data = njt_palloc(dyn_pool, 11);
    if (sname.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&sname, "server_name");
    slisten.data = njt_palloc(dyn_pool, 6);
    if (slisten.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&slisten, "listen");
    slocalhost.data = njt_palloc(dyn_pool, 9);
    if (slocalhost.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&slocalhost, "localhost");


    // 查找对应的block http
    njt_str_t s_http;
    s_http.data = njt_palloc(pool, 4);
    njt_str_set(&s_http, "http");
    http = njt_conf_get_block(root, &s_http, NULL);

    // 查找http下面的server
    for (i = 0; i < http->blocks->nelts; i++) {
        blocks = &((njt_conf_block_t*) http->blocks->elts)[i];
        if (blocks->key.len == 6 
            && njt_strncmp(blocks->key.data, "server", 6) == 0) 
        {
            for (j = 0; j < blocks->value->nelts; j++) {

                svr = &((njt_conf_element_t*)blocks->value->elts)[j];
                if (njt_conf_get_cmd_conf(svr, &sname) == NULL) {
                    if (cf == NULL) {
                        cf = njt_array_create(pool, 1, sizeof(njt_str_t));
                        if (cf == NULL) {
                            return NJT_ERROR;
                        }
                        arg = njt_array_push(cf);
                        njt_memcpy(arg, &sname, sizeof(njt_str_t));
                    }
                    if (njt_conf_set_cmd(pool, svr, cf) != NJT_OK) {
                        return NJT_ERROR;
                    }
                }
                listen = njt_conf_get_cmd_conf(svr, &slisten);
                if (listen != NULL) { // == null will be checked by parse_conf
                    for (k = 0; k < listen->value->nelts; k++) {
                        args = &((njt_array_t *)listen->value->elts)[k];
                        arg = (njt_str_t *)args->elts; // only need the first arg
                        // 如果地址为localhost, 改为127.0.0.1, 这个好，长度不变
                        is_local = arg->len >= 9;
                        if (arg->len >= 9) {
                            for (l = 0; l < 9; l++) { // no need to early break 
                                is_local = is_local && (njt_tolower(arg->data[l])) == slocalhost.data[l];
                            }
                        }
                        if (is_local) {
                            njt_snprintf(arg->data, 9, "127.0.0.1");
                        }
                        // 如果没有端口, 默认加上80, 这是目前的默认值 

                        port = njt_strlchr(arg->data, arg->data + arg->len, ':');
                        if (port == NULL) {
                            if (arg->len < 7) { // 0.0.0.0, only port
                                // 0.0.0.0:port
                                new_arg = njt_palloc(pool, sizeof(njt_str_t));
                                if (new_arg == NULL) {
                                    return NJT_ERROR;
                                }
                                new_arg->data = njt_palloc(pool, 8 + arg->len);
                                if (new_arg->data == NULL) {
                                    return NJT_ERROR;
                                }
                                njt_sprintf(new_arg->data, "0.0.0.0:");
                                njt_memcpy(new_arg->data+8, arg->data, arg->len);
                                new_arg->len = 8 + arg->len;
                                njt_pfree(pool, arg->data);
                                njt_memcpy(arg, new_arg, sizeof(njt_str_t));
                            } else { // add ":80"
                                // address:89
                                new_arg = njt_palloc(pool, sizeof(njt_str_t));
                                if (new_arg == NULL) {
                                    return NJT_ERROR;
                                }
                                new_arg->data = njt_palloc(pool, 3 + arg->len);
                                if (new_arg->data == NULL) {
                                    return NJT_ERROR;
                                }
                                njt_memcpy(new_arg->data, arg->data, arg->len);
                                njt_sprintf(new_arg->data+arg->len, ":80");
                                new_arg->len = 3 + arg->len;
                                njt_pfree(pool, arg->data);
                                njt_memcpy(arg, new_arg, sizeof(njt_str_t)); 
                            }
                        } 
                    }
                }
            }
            break;
        }
    }

    return NJT_OK;
}

njt_int_t
njt_conf_set_cmd(njt_pool_t *pool, njt_conf_element_t *block, njt_array_t *cf) {
    njt_uint_t       i, j, found;
    njt_str_t       *name, *value;
    njt_array_t      *values;
    njt_conf_cmd_t  *cmd;
    
    if (cf == NULL || block == NULL) {
        return NJT_ERROR;
    }

    if (!block->cmds) {
        block->cmds = njt_array_create(pool, 1, sizeof(njt_conf_cmd_t));
        if (!block->cmds) {
            return NJT_ERROR;
        }
    }

    name = cf->elts;
    found = 0;
    for (i = 0; i < block->cmds->nelts; i++) {
        cmd = &((njt_conf_cmd_t *)(block->cmds->elts))[i];
        if (cmd->key.len != name->len) {
            continue;
        }

        // 这里之前用njt_strcmp出过错误，有时ccmd->key_data的len之后不是\0
        if (njt_memcmp(name->data, cmd->key.data, name->len) != 0) {
            continue;
        }

        found = 1;
        break;
    }

    if (!found)
    {
        cmd = njt_array_push(block->cmds);
        if (cmd == NULL) {
            return NJT_ERROR;
        }
        cmd->key.data = njt_palloc(pool, name->len);
        if (cmd->key.data == NULL) {
            return NJT_ERROR;
        }
        cmd->key.len = name->len;
        njt_memcpy(cmd->key.data, name->data, name->len);
        cmd->value = njt_array_create(pool, 1, sizeof(njt_array_t));
    } else {
        // 将 cmd 中的 value 释放
        // TODO free cmd.value
        for (i = 0; i < cmd->value->nelts; i++) {
            values = &((njt_array_t *)cmd->value->elts)[i];
            for (j = 0; j < values->nelts; j++) {
                value = &((njt_str_t *)values->elts)[j];
                njt_pfree(pool, value->data);
            }
        }
        cmd->value->nelts = 0;
    }
    
    return njt_conf_cmd_set_value(pool, cmd, cf);
}

njt_int_t
njt_conf_add_block( njt_pool_t *pool, njt_conf_element_t *parent, 
    njt_conf_element_t *child, njt_str_t *key) 
{
    njt_uint_t              i, found;
    njt_conf_block_t       *block;
    njt_conf_element_t     *bpos;

    found = 0;

    if (!parent->blocks)
    {
        parent->blocks = njt_array_create(pool, 1, sizeof(njt_conf_block_t));
        if (!parent->blocks)
        {
            return NJT_ERROR;
        }
    }
    // find block by key
    for (i = 0; i < parent->blocks->nelts; i++)
    {
        block = &((njt_conf_block_t *)(parent->blocks->elts))[i];
        if (block->key.len != key->len)
        {
            continue;
        }

        if (njt_memcmp(key->data, block->key.data, key->len) != 0)
        {
            continue;
        }

        found = 1;
        break;
    }

    if (!found) {
        block = njt_array_push(parent->blocks);
        if (block == NULL) {
            return NJT_ERROR;
        }
        block->key.data = njt_palloc(pool, key->len);
        if (block->key.data == NULL) {
            return NJT_ERROR;
        }
        block->key.len = key->len;
        njt_memcpy(block->key.data, key->data, key->len);
        block->value = njt_array_create(pool, 1, sizeof(njt_conf_element_t));
        if (block->value == NULL) {
            return NJT_ERROR;
        }
    }

    bpos = njt_array_push(block->value);
    if (bpos == NULL) {
        return NJT_ERROR;
    }
    njt_memcpy(bpos, child, sizeof(njt_conf_element_t));
    bpos->parent = parent;
    
    return NJT_OK;
}

njt_int_t
njt_conf_save_to_file(njt_pool_t *pool, njt_log_t *log, 
    njt_conf_element_t *root, njt_str_t *fname)
{
    size_t      length;
    njt_int_t   rc;
    njt_uint_t  create;
    njt_file_t  file;
    njt_str_t   out;



    njt_memzero(&file, sizeof(njt_file_t));

    file.name = *fname;
    file.log = log;

    create = NJT_FILE_TRUNCATE; // 每次重新生成新文件

    file.fd = njt_open_file(file.name.data, NJT_FILE_RDWR,
                            create, NJT_FILE_DEFAULT_ACCESS);

    if (file.fd == NJT_INVALID_FILE) {
        return NJT_ERROR;
    }

    rc = NJT_OK;
    length = 0;
    if (root == NULL) {
        out.data = njt_palloc(pool, 4);
        if (out.data == NULL) {
            return NJT_ERROR;
        }
        njt_str_set(&out, "null");
        length = 4;
    } else {
        njt_conf_get_json_length(root, &length, 1);
        out.data = njt_palloc(pool, length);
        if (out.data == NULL) {
            return NJT_ERROR;
        }
        out.len = 0;
        njt_conf_get_json_str(root, &out, 1);
    }

    if (njt_write_file(&file, out.data, length, 0) == NJT_ERROR) {
        rc = NJT_ERROR;
    }

    njt_pfree(pool, out.data);
    njt_close_file(file.fd);
    

    return rc;
}


void 
njt_conf_get_json_str(njt_conf_element_t *root, njt_str_t *out, njt_uint_t is_root)
{
    njt_uint_t             i, j, k;
    njt_uint_t             svr_or_loc, sname, listen;
    njt_conf_cmd_t        *cmd;
    njt_array_t           *values;
    njt_str_t             *arg;
    njt_conf_block_t      *blocks;
    njt_conf_element_t    *block;
    u_char *dst;


    dst = out->data + out->len;
    *dst++ = '{'; out->len++;

    if (root->block_name != NULL) {
        dst = njt_sprintf(dst, "\"_key\":"); //"_key":  "block_name",
        cmd = root->block_name;
        if (cmd->value->nelts == 1) {
            // "key": "value",
            values = cmd->value->elts;
            if (values->nelts == 1) {
                // all as string now, change to boolean or number later
                arg = (njt_str_t*)values->elts;// "key": "value",
                dst = njt_sprintf(dst, "\"%V\"", arg);
            } else {
                *dst++ = '['; 
                for (k = 0; k < values->nelts; k++) {
                    arg = &((njt_str_t*)values->elts)[k];
                    dst = njt_sprintf(dst, "\"%V\",", arg);
                }
                dst--; // last ,
                *dst++ = ']'; 
            }
        }
        *dst++ = ','; 
    }

    if (root->cmds) {
        for (i = 0; i < root->cmds->nelts; i++) {
            cmd = &((njt_conf_cmd_t*)root->cmds->elts)[i];
            dst = njt_sprintf(dst, "\"%V\":", &cmd->key); // "key":
            listen = (cmd->key.len == 6 && njt_strncmp(cmd->key.data, "listen", 6) == 0);
            sname = (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server_name", 11) == 0);
            if (cmd->value->nelts == 1 && !listen) {
                // "key": "value",
                values = cmd->value->elts;
                if (values->nelts == 1 && !sname) {
                    // all as string now, change to boolean or number later
                    arg = (njt_str_t*)values->elts;// "key": "value",
                    dst = njt_sprintf(dst, "\"%V\"", arg);
                } else {
                    *dst++ = '['; 
                    for (k = 0; k < values->nelts; k++) {
                        arg = &((njt_str_t*)values->elts)[k];
                        dst = njt_sprintf(dst, "\"%V\",", arg);
                    }
                    if (k) {
                        dst--; // last ,
                    }
                    *dst++ = ']'; 
                    out->len = dst - out->data;
                }
            } else {
                *dst++ = '['; 
                for (j = 0; j < cmd->value->nelts; j++) {
                    *dst++ = '['; 
                    values = &((njt_array_t*)cmd->value->elts)[j];
                    for (k = 0; k < values->nelts; k++) {
                        arg = &((njt_str_t*)values->elts)[k];
                        dst = njt_sprintf(dst, "\"%V\",", arg);
                    }
                    if (k > 0) {
                        dst--; // last ,
                    }
                    *dst++ = ']'; 
                    *dst++ = ','; 
                    out->len = dst - out->data;
                }
                if (j > 0) {
                    dst--; // last ,
                }
                *dst++ = ']'; 
            }
            *dst++ = ','; 
        }
        out->len = dst - out->data;
    }

    if (root->blocks == NULL) {
        dst--;
        *dst++ = '}'; 
        out->len = dst - out->data;
        return;
    }

    for (i = 0; i < root->blocks->nelts; i++) {
        dst = out->data + out->len;
        blocks = &((njt_conf_block_t*)root->blocks->elts)[i];
        dst = njt_sprintf(dst, "\"%V\":", &blocks->key); // "key":
        out->len = dst - out->data;
        svr_or_loc = (blocks->key.len == 6 && njt_strncmp(blocks->key.data, "server", 6) == 0)
                     || (blocks->key.len == 8 && njt_strncmp(blocks->key.data, "location", 8) == 0);
        if (blocks->value->nelts == 1 && !svr_or_loc) {
            // http : {}
            block = blocks->value->elts;
            njt_conf_get_json_str(block, out, 0);
        } else {
            *dst++ = '['; 
            out->len = dst - out->data;
            for (j = 0; j < blocks->value->nelts; j++) {
                block = &((njt_conf_element_t*)blocks->value->elts)[j];
                njt_conf_get_json_str(block, out, 0);
                dst = out->data + out->len;
                *dst++ = ','; 
                out->len = dst - out->data;
            }
            dst = out->data + out->len;
            dst--; // last ,
            *dst++ = ']'; 
        }
        dst = out->data + out->len;
        *dst++ = ','; 
        out->len = dst - out->data;
    }
    
    dst = out->data + out->len;
    dst--;
    *dst++ = '}'; 
    out->len = dst - out->data;
}

static njt_int_t
njt_conf_element_handler(njt_pool_t *pool, njt_conf_t *cf, njt_int_t rc)
{
    // njt_uint_t         i;
    njt_uint_t         j, found; // , found_cmd;
    njt_str_t          *name;
    // njt_command_t      *cmd;
    njt_conf_element_t *cur;
    njt_conf_element_t *new_block, *bpos;
    njt_conf_block_t   *block;
    njt_conf_cmd_t     *ccmd; 

    cur = (njt_conf_element_t*)njt_conf_cur_ptr;
    // // all conditions will be checked in njt_conf_handler() 
    if (rc == NJT_CONF_BLOCK_DONE) {
        njt_conf_cur_ptr = cur->parent;
        return NJT_OK;
    }

    if (rc == NJT_CONF_FILE_DONE) {
        return NJT_OK;
    }

    name = cf->args->elts;
    found = 0;

    if (rc == NJT_OK) {
        if (!cur->cmds) {
            cur->cmds = njt_array_create(pool, 1, sizeof(njt_conf_cmd_t));
            if (!cur->cmds) {
                return NJT_ERROR;
            }
        }
        // find cmd by key
        for (j = 0; j < cur->cmds->nelts; j++) {
            ccmd = &((njt_conf_cmd_t *)(cur->cmds->elts))[j];
            if (ccmd->key.len != name->len) {
                continue;
            }

            // 这里之前用njt_strcmp出过错误，有时ccmd->key_data的len之后不是\0
            if (njt_memcmp(name->data, ccmd->key.data, name->len) != 0) {
                continue;
            }

            found = 1;
            break;
        }

        if (!found) {
            ccmd = njt_array_push(cur->cmds);
            if (ccmd == NULL) {
                return NJT_ERROR;
            }
            ccmd->key.data = njt_palloc(pool, name->len);
            if (ccmd->key.data == NULL) {
                return NJT_ERROR;
            }
            ccmd->key.len = name->len;
            njt_memcpy(ccmd->key.data, name->data, name->len);
            ccmd->value = njt_array_create(pool, 1, sizeof(njt_array_t));
            // ccmd->is_num = 0;
            // ccmd->is_flag = 0;
        }
        // set value to ccmd
        if (njt_conf_cmd_set_args(pool, cf, ccmd) == NJT_ERROR) {
            return NJT_ERROR;
        }
        // if (found_cmd) {
        //     if (cmd->type & NJT_CONF_FLAG) {
        //         // ccmd->is_flag = 1;
        //     }
        // }
        return NJT_OK;
    }

    if (rc == NJT_CONF_BLOCK_START) {
        new_block = njt_pcalloc(pool, sizeof(njt_conf_element_t));
        if (new_block == NULL) {
            return NJT_ERROR;
        }
        if (cf->args->nelts > 1) {
            new_block->block_name = njt_palloc(pool, sizeof(njt_conf_cmd_t));
            if (new_block->block_name == NULL) {
                return NJT_ERROR;
            }
            new_block->block_name->value = njt_array_create(pool, 1, sizeof(njt_array_t));
            if (new_block->block_name->value == NULL) {
                return NJT_ERROR;
            }
            if (njt_conf_cmd_set_args(pool, cf, new_block->block_name) == NJT_ERROR) {
                return NJT_ERROR;
            }
        }

        if (!cur->blocks)
        {
            cur->blocks = njt_array_create(pool, 1, sizeof(njt_conf_block_t));
            if (!cur->blocks)
            {
                return NJT_ERROR;
            }
        }
        // find cmd by key
        for (j = 0; j < cur->blocks->nelts; j++)
        {
            block = &((njt_conf_block_t *)(cur->blocks->elts))[j];
            if (block->key.len != name->len)
            {
                continue;
            }

            if (njt_memcmp(name->data, block->key.data, name->len) != 0)
            {
                continue;
            }

            found = 1;
            break;
        }

        if (!found) {
            block = njt_array_push(cur->blocks);
            if (block == NULL) {
                return NJT_ERROR;
            }
            block->key.data = njt_palloc(pool, name->len);
            if (block->key.data == NULL) {
                return NJT_ERROR;
            }
            block->key.len = name->len;
            njt_memcpy(block->key.data, name->data, name->len);
            block->value = njt_array_create(pool, 1, sizeof(njt_conf_element_t));
            if (block->value == NULL) {
                return NJT_ERROR;
            }
        }

        bpos = njt_array_push(block->value);
        if (bpos == NULL) {
            return NJT_ERROR;
        }
        njt_memcpy(bpos, new_block, sizeof(njt_conf_element_t));
        bpos->parent = cur;
        njt_conf_cur_ptr = bpos;
        
        return NJT_OK;
    }

    return NJT_ERROR;
}

static njt_int_t
njt_conf_handler(njt_conf_t *cf, njt_int_t last)
{
    char           *rv;
    void           *conf, **confp;
    njt_uint_t      i, found;
    njt_str_t      *name;
    njt_command_t  *cmd;

    name = cf->args->elts;

    found = 0;

    for (i = 0; cf->cycle->modules[i]; i++) {

        cmd = cf->cycle->modules[i]->commands;
        if (cmd == NULL) {
            continue;
        }

        for ( /* void */ ; cmd->name.len; cmd++) {

            if (name->len != cmd->name.len) {
                continue;
            }

            if (njt_strcmp(name->data, cmd->name.data) != 0) {
                continue;
            }

            found = 1;

            if (cf->cycle->modules[i]->type != NJT_CONF_MODULE
                && cf->cycle->modules[i]->type != cf->module_type)
            {
                continue;
            }

            /* is the directive's location right ? */

            if (!(cmd->type & cf->cmd_type)) {
                continue;
            }

            if (!(cmd->type & NJT_CONF_BLOCK) && last != NJT_OK) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                  "directive \"%s\" is not terminated by \";\"",
                                  name->data);
                return NJT_ERROR;
            }

            if ((cmd->type & NJT_CONF_BLOCK) && last != NJT_CONF_BLOCK_START) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "directive \"%s\" has no opening \"{\"",
                                   name->data);
                return NJT_ERROR;
            }

            /* is the directive's argument count right ? */

            if (!(cmd->type & NJT_CONF_ANY)) {

                if (cmd->type & NJT_CONF_FLAG) {

                    if (cf->args->nelts != 2) {
                        goto invalid;
                    }

                } else if (cmd->type & NJT_CONF_1MORE) {

                    if (cf->args->nelts < 2) {
                        goto invalid;
                    }

                } else if (cmd->type & NJT_CONF_2MORE) {

                    if (cf->args->nelts < 3) {
                        goto invalid;
                    }

                } else if (cf->args->nelts > NJT_CONF_MAX_ARGS) {

                    goto invalid;

                } else if (!(cmd->type & argument_number[cf->args->nelts - 1]))
                {
                    goto invalid;
                }
            }

            /* set up the directive's configuration context */

            conf = NULL;

            if (cmd->type & NJT_DIRECT_CONF) {
                conf = ((void **) cf->ctx)[cf->cycle->modules[i]->index];

            } else if (cmd->type & NJT_MAIN_CONF) {
                conf = &(((void **) cf->ctx)[cf->cycle->modules[i]->index]);

            } else if (cf->ctx) {
                confp = *(void **) ((char *) cf->ctx + cmd->conf);

                if (confp) {
                    conf = confp[cf->cycle->modules[i]->ctx_index];
                }
            }

            rv = cmd->set(cf, cmd, conf);

            if (rv == NJT_CONF_OK) {
                return NJT_OK;
            }

            if (rv == NJT_CONF_ERROR) {
                return NJT_ERROR;
            }

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "\"%s\" directive %s", name->data, rv);

            return NJT_ERROR;
        }
    }

    if (found) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%s\" directive is not allowed here", name->data);

        return NJT_ERROR;
    }

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "unknown directive \"%s\"", name->data);

    return NJT_ERROR;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid number of arguments in \"%s\" directive",
                       name->data);

    return NJT_ERROR;
}


static njt_int_t
njt_conf_read_token(njt_conf_t *cf)
{
    u_char      *start, ch, *src, *dst;
    off_t        file_size;
    size_t       len;
    ssize_t      n, size;
    njt_uint_t   found, need_space, last_space, sharp_comment, variable;
    njt_uint_t   quoted, s_quoted, d_quoted, start_line;
    njt_str_t   *word;
    njt_buf_t   *b, *dump;

    found = 0;
    need_space = 0;
    last_space = 1;
    sharp_comment = 0;
    variable = 0;
    quoted = 0;
    s_quoted = 0;
    d_quoted = 0;

    cf->args->nelts = 0;
    b = cf->conf_file->buffer;
    dump = cf->conf_file->dump;
    start = b->pos;
    start_line = cf->conf_file->line;

    file_size = njt_file_size(&cf->conf_file->file.info);

    for ( ;; ) {

        if (b->pos >= b->last) {

            if (cf->conf_file->file.offset >= file_size) {

                if (cf->args->nelts > 0 || !last_space) {

                    if (cf->conf_file->file.fd == NJT_INVALID_FILE) {
                        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                           "unexpected end of parameter, "
                                           "expecting \";\"");
                        return NJT_ERROR;
                    }

                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                  "unexpected end of file, "
                                  "expecting \";\" or \"}\"");
                    return NJT_ERROR;
                }

                return NJT_CONF_FILE_DONE;
            }

            len = b->pos - start;

            if (len == NJT_CONF_BUFFER) {
                cf->conf_file->line = start_line;

                if (d_quoted) {
                    ch = '"';

                } else if (s_quoted) {
                    ch = '\'';

                } else {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "too long parameter \"%*s...\" started",
                                       10, start);
                    return NJT_ERROR;
                }

                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "too long parameter, probably "
                                   "missing terminating \"%c\" character", ch);
                return NJT_ERROR;
            }

            if (len) {
                njt_memmove(b->start, start, len);
            }

            size = (ssize_t) (file_size - cf->conf_file->file.offset);

            if (size > b->end - (b->start + len)) {
                size = b->end - (b->start + len);
            }

            n = njt_read_file(&cf->conf_file->file, b->start + len, size,
                              cf->conf_file->file.offset);

            if (n == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (n != size) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   njt_read_file_n " returned "
                                   "only %z bytes instead of %z",
                                   n, size);
                return NJT_ERROR;
            }

            b->pos = b->start + len;
            b->last = b->pos + n;
            start = b->start;

            if (dump) {
                dump->last = njt_cpymem(dump->last, b->pos, size);
            }
        }

        ch = *b->pos++;

        if (ch == LF) {
            cf->conf_file->line++;

            if (sharp_comment) {
                sharp_comment = 0;
            }
        }

        if (sharp_comment) {
            continue;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        if (need_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                last_space = 1;
                need_space = 0;
                continue;
            }

            if (ch == ';') {
                return NJT_OK;
            }

            if (ch == '{') {
                return NJT_CONF_BLOCK_START;
            }

            if (ch == ')') {
                last_space = 1;
                need_space = 0;

            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "unexpected \"%c\"", ch);
                return NJT_ERROR;
            }
        }

        if (last_space) {

            start = b->pos - 1;
            start_line = cf->conf_file->line;

            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                continue;
            }

            switch (ch) {

            case ';':
            case '{':
                if (cf->args->nelts == 0) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "unexpected \"%c\"", ch);
                    return NJT_ERROR;
                }

                if (ch == '{') {
                    return NJT_CONF_BLOCK_START;
                }

                return NJT_OK;

            case '}':
                if (cf->args->nelts != 0) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "unexpected \"}\"");
                    return NJT_ERROR;
                }

                return NJT_CONF_BLOCK_DONE;

            case '#':
                sharp_comment = 1;
                continue;

            case '\\':
                quoted = 1;
                last_space = 0;
                continue;

            case '"':
                start++;
                d_quoted = 1;
                last_space = 0;
                continue;

            case '\'':
                start++;
                s_quoted = 1;
                last_space = 0;
                continue;

            case '$':
                variable = 1;
                last_space = 0;
                continue;

            default:
                last_space = 0;
            }

        } else {
            if (ch == '{' && variable) {
                continue;
            }

            variable = 0;

            if (ch == '\\') {
                quoted = 1;
                continue;
            }

            if (ch == '$') {
                variable = 1;
                continue;
            }

            if (d_quoted) {
                if (ch == '"') {
                    d_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (s_quoted) {
                if (ch == '\'') {
                    s_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
                       || ch == ';' || ch == '{')
            {
                last_space = 1;
                found = 1;
            }

            if (found) {
                word = njt_array_push(cf->args);
                if (word == NULL) {
                    return NJT_ERROR;
                }
                word->data = njt_pnalloc(cf->pool, b->pos - 1 - start + 1);
                if (word->data == NULL) {
                    return NJT_ERROR;
                }

                for (dst = word->data, src = start, len = 0;
                     src < b->pos - 1;
                     len++)
                {
                    if (*src == '\\') {
                        switch (src[1]) {
                        case '"':
                        case '\'':
                        case '\\':
                            src++;
                            break;

                        case 't':
                            *dst++ = '\t';
                            src += 2;
                            continue;

                        case 'r':
                            *dst++ = '\r';
                            src += 2;
                            continue;

                        case 'n':
                            *dst++ = '\n';
                            src += 2;
                            continue;
                        }

                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;

                if (ch == ';') {
                    return NJT_OK;
                }

                if (ch == '{') {
                    return NJT_CONF_BLOCK_START;
                }

                found = 0;
            }
        }
    }
}


char *
njt_conf_include(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char        *rv;
    njt_int_t    n;
    njt_str_t   *value, file, name;
    njt_glob_t   gl;

    value = cf->args->elts;
    file = value[1];

    njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

    if (njt_conf_full_name(cf->cycle, &file, 1) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (strpbrk((char *) file.data, "*?[") == NULL) {

        njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        return njt_conf_parse(cf, &file);
    }

    njt_memzero(&gl, sizeof(njt_glob_t));

    gl.pattern = file.data;
    gl.log = cf->log;
    gl.test = 1;

    if (njt_open_glob(&gl) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           njt_open_glob_n " \"%s\" failed", file.data);
        return NJT_CONF_ERROR;
    }

    rv = NJT_CONF_OK;

    for ( ;; ) {
        n = njt_read_glob(&gl, &name);

        if (n != NJT_OK) {
            break;
        }

        file.len = name.len++;
        file.data = njt_pstrdup(cf->pool, &name);
        if (file.data == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        rv = njt_conf_parse(cf, &file);

        if (rv != NJT_CONF_OK) {
            break;
        }
    }

    njt_close_glob(&gl);

    return rv;
}


njt_int_t
njt_conf_full_name(njt_cycle_t *cycle, njt_str_t *name, njt_uint_t conf_prefix)
{
    njt_str_t  *prefix;

    prefix = conf_prefix ? &cycle->conf_prefix : &cycle->prefix;

    return njt_get_full_name(cycle->pool, prefix, name);
}


njt_open_file_t *
njt_conf_open_file(njt_cycle_t *cycle, njt_str_t *name)
{
    njt_str_t         full;
    njt_uint_t        i;
    njt_list_part_t  *part;
    njt_open_file_t  *file;

#if (NJT_SUPPRESS_WARN)
    njt_str_null(&full);
#endif

    if (name->len) {
        full = *name;

        if (njt_conf_full_name(cycle, &full, 0) != NJT_OK) {
            return NULL;
        }

        part = &cycle->open_files.part;
        file = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                file = part->elts;
                i = 0;
            }

            if (full.len != file[i].name.len) {
                continue;
            }

            if (njt_strcmp(full.data, file[i].name.data) == 0) {
                return &file[i];
            }
        }
    }

    file = njt_list_push(&cycle->open_files);
    if (file == NULL) {
        return NULL;
    }

    if (name->len) {
        file->fd = NJT_INVALID_FILE;
        file->name = full;

    } else {
        file->fd = njt_stderr;
        file->name = *name;
    }

    file->flush = NULL;
    file->data = NULL;

    return file;
}


static void
njt_conf_flush_files(njt_cycle_t *cycle)
{
    njt_uint_t        i;
    njt_list_part_t  *part;
    njt_open_file_t  *file;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, cycle->log, 0, "flush files");

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].flush) {
            file[i].flush(&file[i], cycle->log);
        }
    }
}


void njt_cdecl
njt_conf_log_error(njt_uint_t level, njt_conf_t *cf, njt_err_t err,
    const char *fmt, ...)
{
    u_char   errstr[NJT_MAX_CONF_ERRSTR], *p, *last;
    va_list  args;

    last = errstr + NJT_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = njt_vslprintf(errstr, last, fmt, args);
    va_end(args);

    if (err) {
        p = njt_log_errno(p, last, err);
    }

    if (cf->conf_file == NULL) {
        njt_log_error(level, cf->log, 0, "%*s", p - errstr, errstr);
        return;
    }

    if (cf->conf_file->file.fd == NJT_INVALID_FILE) {
        njt_log_error(level, cf->log, 0, "%*s in command line",
                      p - errstr, errstr);
        return;
    }
    njt_log_error(level, cf->log, 0, "%*s in %s:%ui",
                  p - errstr, errstr,
                  cf->conf_file->file.name.data, cf->conf_file->line);
    //by zyg	
    if(cf->errstr){
    	p = njt_snprintf(cf->errstr->data,cf->errstr->len,"%*s in %s:%ui",p - errstr, errstr,cf->conf_file->file.name.data, cf->conf_file->line);
    	cf->errstr->len = p - cf->errstr->data;
    }
    //end
}


char *
njt_conf_set_flag_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t        *value;
    njt_flag_t       *fp;
    njt_conf_post_t  *post;

    fp = (njt_flag_t *) (p + cmd->offset);

    if (*fp != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        *fp = 1;

    } else if (njt_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        *fp = 0;

    } else {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return NJT_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, fp);
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_str_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t        *field, *value;
    njt_conf_post_t  *post;

    field = (njt_str_t *) (p + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = value[1];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_str_array_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t         *value, *s;
    njt_array_t      **a;
    njt_conf_post_t   *post;

    a = (njt_array_t **) (p + cmd->offset);

    if (*a == NJT_CONF_UNSET_PTR) {
        *a = njt_array_create(cf->pool, 4, sizeof(njt_str_t));
        if (*a == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    s = njt_array_push(*a);
    if (s == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    *s = value[1];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, s);
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_keyval_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t         *value;
    njt_array_t      **a;
    njt_keyval_t      *kv;
    njt_conf_post_t   *post;

    a = (njt_array_t **) (p + cmd->offset);

    if (*a == NJT_CONF_UNSET_PTR || *a == NULL) {
        *a = njt_array_create(cf->pool, 4, sizeof(njt_keyval_t));
        if (*a == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    kv = njt_array_push(*a);
    if (kv == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    kv->key = value[1];
    kv->value = value[2];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, kv);
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_num_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_int_t        *np;
    njt_str_t        *value;
    njt_conf_post_t  *post;


    np = (njt_int_t *) (p + cmd->offset);

    if (*np != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;
    *np = njt_atoi(value[1].data, value[1].len);
    if (*np == NJT_ERROR) {
        return "invalid number";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_size_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    size_t           *sp;
    njt_str_t        *value;
    njt_conf_post_t  *post;


    sp = (size_t *) (p + cmd->offset);
    if (*sp != NJT_CONF_UNSET_SIZE) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *sp = njt_parse_size(&value[1]);
    if (*sp == (size_t) NJT_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sp);
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_off_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    off_t            *op;
    njt_str_t        *value;
    njt_conf_post_t  *post;


    op = (off_t *) (p + cmd->offset);
    if (*op != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *op = njt_parse_offset(&value[1]);
    if (*op == (off_t) NJT_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, op);
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_msec_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_msec_t       *msp;
    njt_str_t        *value;
    njt_conf_post_t  *post;


    msp = (njt_msec_t *) (p + cmd->offset);
    if (*msp != NJT_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *msp = njt_parse_time(&value[1], 0);
    if (*msp == (njt_msec_t) NJT_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, msp);
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_sec_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    time_t           *sp;
    njt_str_t        *value;
    njt_conf_post_t  *post;


    sp = (time_t *) (p + cmd->offset);
    if (*sp != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *sp = njt_parse_time(&value[1], 1);
    if (*sp == (time_t) NJT_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sp);
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_bufs_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char *p = conf;

    njt_str_t   *value;
    njt_bufs_t  *bufs;


    bufs = (njt_bufs_t *) (p + cmd->offset);
    if (bufs->num) {
        return "is duplicate";
    }

    value = cf->args->elts;

    bufs->num = njt_atoi(value[1].data, value[1].len);
    if (bufs->num == NJT_ERROR || bufs->num == 0) {
        return "invalid value";
    }

    bufs->size = njt_parse_size(&value[2]);
    if (bufs->size == (size_t) NJT_ERROR || bufs->size == 0) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_enum_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_uint_t       *np, i;
    njt_str_t        *value;
    njt_conf_enum_t  *e;

    np = (njt_uint_t *) (p + cmd->offset);

    if (*np != NJT_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    e = cmd->post;

    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len != value[1].len
            || njt_strcasecmp(e[i].name.data, value[1].data) != 0)
        {
            continue;
        }

        *np = e[i].value;

        return NJT_CONF_OK;
    }

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid value \"%s\"", value[1].data);

    return NJT_CONF_ERROR;
}


char *
njt_conf_set_bitmask_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_uint_t          *np, i, m;
    njt_str_t           *value;
    njt_conf_bitmask_t  *mask;


    np = (njt_uint_t *) (p + cmd->offset);
    value = cf->args->elts;
    mask = cmd->post;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                || njt_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (*np & mask[m].mask) {
                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                *np |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


#if 0

char *
njt_conf_unsupported(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    return "unsupported on this platform";
}

#endif


char *
njt_conf_deprecated(njt_conf_t *cf, void *post, void *data)
{
    njt_conf_deprecated_t  *d = post;

    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "the \"%s\" directive is deprecated, "
                       "use the \"%s\" directive instead",
                       d->old_name, d->new_name);

    return NJT_CONF_OK;
}


char *
njt_conf_check_num_bounds(njt_conf_t *cf, void *post, void *data)
{
    njt_conf_num_bounds_t  *bounds = post;
    njt_int_t  *np = data;

    if (bounds->high == -1) {
        if (*np >= bounds->low) {
            return NJT_CONF_OK;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "value must be equal to or greater than %i",
                           bounds->low);

        return NJT_CONF_ERROR;
    }

    if (*np >= bounds->low && *np <= bounds->high) {
        return NJT_CONF_OK;
    }

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "value must be between %i and %i",
                       bounds->low, bounds->high);

    return NJT_CONF_ERROR;
}

njt_int_t
njt_conf_read_memory_token(njt_conf_t *cf,njt_str_t data)
{
    u_char      *start, ch, *src, *dst;
    size_t       len;
    njt_uint_t   found, need_space, last_space, sharp_comment, variable;
    njt_uint_t   quoted, s_quoted, d_quoted;
    njt_str_t   *word;
    njt_buf_t   *b,  new_buf;

    found = 0;
    need_space = 0;
    last_space = 1;
    sharp_comment = 0;
    variable = 0;
    quoted = 0;
    s_quoted = 0;
    d_quoted = 0;

    cf->args->nelts = 0;
    njt_memzero(&new_buf,sizeof(new_buf));

    b = &new_buf;
    new_buf.start = data.data;
    new_buf.end = data.data + data.len;

    new_buf.pos = new_buf.start;
    new_buf.last = new_buf.end;
    start = b->pos;


    for ( ;; ) {

        if (b->pos >= b->last) {
	    if(start <= b->last) {
		word = njt_array_push(cf->args);
                if (word == NULL) {
                    return NJT_ERROR;
                }
                word->data = njt_pnalloc(cf->pool, b->pos - 1 - start + 1);
                if (word->data == NULL) {
                    return NJT_ERROR;
                }

                for (dst = word->data, src = start, len = 0;
                     src < b->pos;
                     len++)
                {
                    if (*src == '\\') {
                        switch (src[1]) {
                        case '"':
                        case '\'':
                        case '\\':
                            src++;
                            break;

                        case 't':
                            *dst++ = '\t';
                            src += 2;
                            continue;

                        case 'r':
                            *dst++ = '\r';
                            src += 2;
                            continue;

                        case 'n':
                            *dst++ = '\n';
                            src += 2;
                            continue;
                        }

                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;
	    }
	    break;
        }

        ch = *b->pos++;

        if (ch == LF) {
            cf->conf_file->line++;

            if (sharp_comment) {
                sharp_comment = 0;
            }
        }

        if (sharp_comment) {
            continue;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        if (need_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                last_space = 1;
                need_space = 0;
                continue;
            }

            if (ch == ';') {
                return NJT_OK;
            }

            if (ch == '{') {
                return NJT_CONF_BLOCK_START;
            }

            if (ch == ')') {
                last_space = 1;
                need_space = 0;

            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "unexpected \"%c\"", ch);
                return NJT_ERROR;
            }
        }

        if (last_space) {

            start = b->pos - 1;

            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                continue;
            }

            switch (ch) {

            case ';':
            case '{':
                if (cf->args->nelts == 0) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "unexpected \"%c\"", ch);
                    return NJT_ERROR;
                }

                if (ch == '{') {
                    return NJT_CONF_BLOCK_START;
                }

                return NJT_OK;

            case '}':
                if (cf->args->nelts != 0) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "unexpected \"}\"");
                    return NJT_ERROR;
                }

                return NJT_CONF_BLOCK_DONE;

            case '#':
                sharp_comment = 1;
                continue;

            case '\\':
                quoted = 1;
                last_space = 0;
                continue;

            case '"':
                start++;
                d_quoted = 1;
                last_space = 0;
                continue;

            case '\'':
                start++;
                s_quoted = 1;
                last_space = 0;
                continue;

            case '$':
                variable = 1;
                last_space = 0;
                continue;

            default:
                last_space = 0;
            }

        } else {
            if (ch == '{' && variable) {
                continue;
            }

            variable = 0;

            if (ch == '\\') {
                quoted = 1;
                continue;
            }

            if (ch == '$') {
                variable = 1;
                continue;
            }

            if (d_quoted) {
                if (ch == '"') {
                    d_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (s_quoted) {
                if (ch == '\'') {
                    s_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
                       || ch == ';' || ch == '{')
            {
                last_space = 1;
                found = 1;
            }

            if (found) {
                word = njt_array_push(cf->args);
                if (word == NULL) {
                    return NJT_ERROR;
                }
                word->data = njt_pnalloc(cf->pool, b->pos - 1 - start + 1);
                if (word->data == NULL) {
                    return NJT_ERROR;
                }

                for (dst = word->data, src = start, len = 0;
                     src < b->pos - 1;
                     len++)
                {
                    if (*src == '\\') {
                        switch (src[1]) {
                        case '"':
                        case '\'':
                        case '\\':
                            src++;
                            break;

                        case 't':
                            *dst++ = '\t';
                            src += 2;
                            continue;

                        case 'r':
                            *dst++ = '\r';
                            src += 2;
                            continue;

                        case 'n':
                            *dst++ = '\n';
                            src += 2;
                            continue;
                        }

                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;

                if (ch == ';') {
                    return NJT_OK;
                }

                if (ch == '{') {
                    return NJT_CONF_BLOCK_START;
                }

                found = 0;
            }
        }
    }
  return NJT_OK;
}
