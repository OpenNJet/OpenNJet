
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_str_util.h>

void njt_conf_free_element(njt_pool_t *pool, njt_conf_element_t *block); // by lcm

void
njt_conf_init_conf_parse(njt_conf_element_t *root, njt_pool_t* pool) {
    njt_conf_cur_ptr = root;
    njt_conf_pool_ptr = pool;
}

void
njt_conf_finish_conf_parse() {
    njt_conf_pool_ptr = NULL;
}


njt_str_t njt_conf_get_command_unique_name(njt_pool_t *pool,njt_str_t src) {
    njt_conf_t  cf;
    njt_str_t   full_name, *value, new_src;
    u_char*     index;
    njt_uint_t  len, i;

    full_name.len = 0;
    full_name.data = NULL;
    njt_memzero(&cf, sizeof(njt_conf_t));
    cf.pool = pool;
    cf.temp_pool = pool;
    cf.log = njt_cycle->log;


    //njt_str_set(&src,"~\\");
    if(src.len == 0) {
        return full_name;
    }

    new_src.len = src.len + 3;
    new_src.data = njt_pcalloc(pool,new_src.len);  //add " {"

    if (new_src.data == NULL){
        return full_name;
    }

    njt_memcpy(new_src.data,src.data,src.len);
    new_src.data[new_src.len - 3] = ' ';
    new_src.data[new_src.len - 2] = '{';
    new_src.data[new_src.len - 1] = '\0';


    cf.args = njt_array_create(cf.pool, 10, sizeof(njt_str_t));
    if (cf.args == NULL) {
        return full_name;
    }

    njt_conf_read_memory_token(&cf,new_src);
    len =0;
    value = cf.args->elts;

    for(i = 0; i < cf.args->nelts; i++){
        len += value[i].len;
    }

    index = njt_pcalloc(pool,len);

    if (index == NULL){
        return full_name;
    }

    full_name.data = index;

    for(i = 0; i < cf.args->nelts; i++){
        njt_memcpy(index,value[i].data,value[i].len);
        index += value[i].len;
    }

    full_name.len = len;

    return full_name;
}

njt_int_t njt_conf_http_location_full_name_cmp(njt_str_t escaped_full_name,njt_str_t src) {

	njt_pool_t  *pool;
	njt_str_t   full_name, command1, command2;

	pool = njt_create_pool(1024, njt_cycle->log);
	if(pool == NULL) {
		return NJT_ERROR;
	}

    full_name = delete_escape(pool, escaped_full_name);
	command1 = njt_conf_get_command_unique_name(pool, full_name);
	command2 = njt_conf_get_command_unique_name(pool, src);

	if(command1.len == command2.len && njt_strncmp(command1.data,command2.data,command1.len) == 0) {
        njt_destroy_pool(pool);
        return NJT_OK;
	}

	njt_destroy_pool(pool);

	return NJT_ERROR;
}


static njt_int_t
njt_conf_cmd_set_args(njt_pool_t *pool, njt_conf_t *cf, njt_conf_cmd_t *ccmd){
    njt_uint_t      i, j;
    njt_uint_t      need_escape, is_location;
    njt_str_t      *arg, *value, *ori_value;
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
    is_location = arg->len == 8
                  && njt_strncmp(arg->data, "location", 8) == 0;

    if (is_location) {
        vlen =0;
        vlen =0;
        ori_value = cf->ori_args->elts;

        for(i = 1; i < cf->ori_args->nelts; i++){
            //len += value[i].len+1;
            vlen += ori_value[i].len + 1;
        }

        index.data = njt_pcalloc(pool,vlen+1);
        index.len = 0;

        if (index.data == NULL){
            return NJT_ERROR;
        }

        for(i = 1; i < cf->ori_args->nelts; i++){
            njt_memcpy(index.data + index.len, ori_value[i].data, ori_value[i].len);
            index.len += ori_value[i].len;
            *(index.data + index.len) = (u_char)' ';
            index.len ++;
        }

        if (index.len > 0) {
            index.len --;
        }
        arg = &index;
    }


    for (i = 1; i < cf->args->nelts; i++) {
        value = njt_array_push(pos);
        if (value == NULL) {
            return NJT_ERROR;
        }
        if (!is_location) { // is_location arg = &index
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
        if (is_location) {
            break;
        }
    }



    return NJT_OK;
}


njt_int_t
njt_conf_dyn_check_lua_block(njt_str_t *name) {
    // "lua_load_resty_core" deprecated
    // "lua_thread_cache_max_entries" njt_conf_set_num_slot,
    // "lua_max_running_timers"       njt_conf_set_num_slot,
    // "lua_max_pending_timers"       njt_conf_set_num_slot,
    // "lua_shared_dict"              njt_http_lua_shared_dict, can parse
    // "lua_capture_error_log"        njt_http_lua_capture_error_log, can parse
    // "lua_sa_restart"               njt_conf_set_flag_slot,
    // "lua_regex_cache_max_entries   njt_http_lua_regex_cache_max_entries, can parse
    // "lua_regex_match_limit"        njt_http_lua_regex_match_limit, can parse
    // "lua_package_cpath"            njt_http_lua_package_cpath, can parse
    // "lua_package_path"             njt_http_lua_package_path, can parse
    // "lua_code_cache"               njt_http_lua_code_cache, can parse
    // "lua_need_request_body"        njt_conf_set_flag_slot,
    // "lua_transform_underscores_in_response_headers"
    //                                njt_conf_set_flag_slot,
    // "lua_socket_log_errors"        njt_conf_set_flag_slot,
    // "init_by_lua_block"
    if (name->len == 17 && njt_strncmp(name->data, "init_by_lua_block", 17) == NJT_OK) {
        return NJT_OK;
    }

    // "init_by_lua"                   njt_http_lua_init_by_lua, 这个处理一行
    // "init_by_lua_file"),            njt_http_lua_init_by_lua, 这个处理一行
    // "init_worker_by_lua_block"
    if (name->len == 24 && njt_strncmp(name->data, "init_worker_by_lua_block", 24) == NJT_OK) {
        return NJT_OK;
    }

    // "init_worker_by_lua"            njt_http_lua_init_worker_by_lua, 这个处理一行
    // "init_worker_by_lua_file"       njt_http_lua_init_worker_by_lua, 这个处理一行

    // "exit_worker_by_lua_block"
    if (name->len == 24 && njt_strncmp(name->data, "exit_worker_by_lua_block", 24) == NJT_OK) {
        return NJT_OK;
    }

    // "exit_worker_by_lua_file"       njt_http_lua_exit_worker_by_lua, 这个处理一行

#if defined(NDK) && NDK
    /* set_by_lua_block $res { inline Lua code } */
    // "set_by_lua_block"
    if (name->len == 16 && njt_strncmp(name->data, "set_by_lua_block", 16) == NJT_OK) {
        return NJT_OK;
    }

    /* set_by_lua $res <inline script> [$arg1 [$arg2 [...]]] */
    // "set_by_lua"                      njt_http_lua_set_by_lua, 这个处理一行
    /* set_by_lua_file $res rel/or/abs/path/to/script [$arg1 [$arg2 [..]]] */
    // "set_by_lua_file"                 njt_http_lua_set_by_lua_file, 这个处理一行
#endif

    /* rewrite_by_lua "<inline script>" */
    // "rewrite_by_lua"                  njt_http_lua_rewrite_by_lua, 这个处理一行
    /* rewrite_by_lua_block { <inline script> } */
    // "rewrite_by_lua_block",
    if (name->len == 20 && njt_strncmp(name->data, "rewrite_by_lua_block", 20) == NJT_OK) {
        return NJT_OK;
    }

    /* access_by_lua "<inline script>" */
    // "access_by_lua"                   njt_http_lua_access_by_lua, 这个处理一行
    /* access_by_lua_block { <inline script> } */
    if (name->len == 19 && njt_strncmp(name->data, "access_by_lua_block", 19) == NJT_OK) {
        return NJT_OK;
    }

    /* content_by_lua "<inline script>" */
    // "content_by_lua")                 njt_http_lua_content_by_lua, 这个处理一行
    /* content_by_lua_block { <inline script> } */
    if (name->len == 20 && njt_strncmp(name->data, "content_by_lua_block", 20) == NJT_OK) {
        return NJT_OK;
    }

    // in stream lua
    if (name->len == 20 && njt_strncmp(name->data, "preread_by_lua_block", 20) == NJT_OK) {
        return NJT_OK;
    }

    /* log_by_lua <inline script> */
    // "log_by_lua"                       njt_http_lua_log_by_lua, 这个处理一行
    // "rewrite_by_lua_file"),            njt_http_lua_rewrite_by_lua, 这个处理一行
    /* log_by_lua_block { <inline script> } */
    if (name->len == 16 && njt_strncmp(name->data, "log_by_lua_block", 16) == NJT_OK) {
        return NJT_OK;
    }

    // "rewrite_by_lua_no_postpone"        njt_conf_set_flag_slot,
    // "access_by_lua_file"                njt_http_lua_access_by_lua, 一行
    // "access_by_lua_no_postpone")        njt_conf_set_flag_slot,
    /* content_by_lua_file rel/or/abs/path/to/script */
    // "content_by_lua_file"               njt_http_lua_content_by_lua, 一行
    // "log_by_lua_file")                  njt_http_lua_log_by_lua, 一行
    /* header_filter_by_lua <inline script> */
    // "header_filter_by_lua"              njt_http_lua_header_filter_by_lua, 一行
    /* header_filter_by_lua_block { <inline script> } */
    if (name->len == 26 && njt_strncmp(name->data, "header_filter_by_lua_block", 26) == NJT_OK) {
        return NJT_OK;
    }

    // "header_filter_by_lua_file          njt_http_lua_header_filter_by_lua, 一行
    // "body_filter_by_lua"                njt_http_lua_body_filter_by_lua, 一行
    // "body_filter_by_lua_file"),         njt_http_lua_body_filter_by_lua, 一行
    /* body_filter_by_lua_block { <inline script> } */
    if (name->len == 24 && njt_strncmp(name->data, "body_filter_by_lua_block", 24) == NJT_OK) {
        return NJT_OK;
    }

    // "balancer_by_lua_block"
    if (name->len == 21 && njt_strncmp(name->data, "balancer_by_lua_block", 21) == NJT_OK) {
        return NJT_OK;
    }

    // "balancer_by_lua_file"                njt_http_lua_balancer_by_lua, one line
    // "lua_socket_keepalive_timeout"        njt_conf_set_msec_slot,
    // "lua_socket_connect_timeout"          njt_conf_set_msec_slot,
    // "balancer_by_lua_file"                njt_http_lua_balancer_by_lua, one line
    // "lua_socket_keepalive_timeout"        njt_conf_set_msec_slot
    // "lua_socket_connect_timeout"          njt_conf_set_msec_slot
    // "lua_socket_send_timeout"             njt_conf_set_msec_slot,
    // "lua_socket_send_lowat"               njt_conf_set_size_slot,
    // "lua_socket_buffer_size"              njt_conf_set_size_slot,
    // "lua_socket_pool_size")               njt_conf_set_num_slot,
    // "lua_socket_read_timeout"             njt_conf_set_msec_slot,
    // "lua_http10_buffering"                njt_conf_set_flag_slot,
    // "lua_check_client_abort"              njt_conf_set_flag_slot,
    // "lua_use_default_type"                njt_conf_set_flag_slot,

#if (NJT_HTTP_SSL)

    // "lua_ssl_protocols"                   njt_conf_set_bitmask_slot,
    // "lua_ssl_ciphers"                     njt_conf_set_str_slot,
    // "ssl_client_hello_by_lua_block"
    if (name->len == 29 && njt_strncmp(name->data, "ssl_client_hello_by_lua_block", 29) == NJT_OK) {
        return NJT_OK;
    }

    // "ssl_client_hello_by_lua_file"        njt_http_lua_ssl_client_hello_by_lua, one line
    // "ssl_certificate_by_lua_block"
    if (name->len == 25 && njt_strncmp(name->data, "ssl_certificate_lua_block", 25) == NJT_OK) {
        return NJT_OK;
    }

    // "ssl_certificate_by_lua_file"         njt_http_lua_ssl_cert_by_lua, one line
    // "ssl_session_store_by_lua_file"       njt_http_lua_ssl_sess_store_by_lua, one line
    // "ssl_session_fetch_by_lua_block",
    if (name->len == 30 && njt_strncmp(name->data, "ssl_session_fetch_by_lua_block", 30) == NJT_OK) {
        return NJT_OK;
    }

    // "ssl_session_fetch_by_lua_file"       njt_http_lua_ssl_sess_fetch_by_lua, one line
    // "lua_ssl_verify_depth"                njt_conf_set_num_slot
    // "lua_ssl_trusted_certificate"         njt_conf_set_str_slot,
    // "lua_ssl_crl"                         njt_conf_set_str_slot,

#if (njet_version >= 1019004)
    // "lua_ssl_conf_command"                njt_conf_set_keyval_slot,
#endif
#endif  /* NJT_HTTP_SSL */

    // "lua_malloc_trim"                     njt_http_lua_malloc_trim,
    // "lua_worker_thread_vm_pool_size"      njt_conf_set_num_slot,
    // njt_null_command
    return NJT_ERROR;
}

njt_int_t
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
        // printf("rc = NJT_CONF_BLOCK_DONE \n");
        return NJT_OK;
    }

    if (rc == NJT_CONF_FILE_DONE) {
        return NJT_OK;
    }

    name = cf->args->elts;

    // if (name->len == 20 && njt_strncmp(name->data, "content_by_lua_block", 20) == NJT_OK) {
    //     return NJT_OK;
    // }
    // if (name->len == 19 && njt_strncmp(name->data, "access_by_lua_block", 19) == NJT_OK) {
    //     return NJT_OK;
    // }
    found = 0;

    if (rc == NJT_OK) {
        if (!cur->cmds) {
            cur->cmds = njt_array_create(pool, 1, sizeof(njt_conf_cmd_t));
            if (!cur->cmds) {
                return NJT_ERROR;
            }
        }
        // find cmd by keygi
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
            new_block->block_name = njt_pcalloc(pool, sizeof(njt_conf_cmd_t));
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
            if (!cur->blocks) {
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


        // for lua block
        if (njt_conf_dyn_check_lua_block(name) == NJT_OK) {
            njt_conf_cur_ptr = cur;
            // return NJT_OK;
        }
        
        return NJT_OK;
    }

    return NJT_ERROR;
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
    njt_pfree(pool, tmp); // **** need check

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
            // printf("key: %s \n", cmd->key.data);
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
        if (root->cmds == NULL && root->block_name == NULL) {
            *length += 1;
        }
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
            if (j == 0) {
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
    ret = njt_conf_get_block(njt_cycle->conf_root, &http, NULL);
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
    ret = njt_conf_get_loc_block(cur, &loc, sub_name);
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
    if (cur == NULL || cur->blocks == NULL || cur->blocks->nelts == 0) {
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
njt_conf_get_loc_block( njt_conf_element_t *cur,
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
    if (cur == NULL || cur->blocks == NULL || cur->blocks->nelts == 0) {
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
                    same = 0;

                    if (args->nelts == sub_names->nelts){
                        for (k = 0; k < args->nelts; k++) {
                            arg = &((njt_str_t*)args->elts)[k];
                            sub_name = &((njt_str_t*)sub_names->elts)[k];
                            if (njt_conf_http_location_full_name_cmp(*arg, *sub_name) == NJT_OK) {
                                same++;
                            } else {
                                break;
                            }
                        }
                        if (same == args->nelts) {
                            return block;
                        }
                    }
                }
            }

        }
    }
    return NULL;
};

njt_uint_t njt_match_case_insensitive(njt_str_t *s, u_char *txt, njt_uint_t len) {
    njt_uint_t i;
    
    for (i = 0; i < len; i++) {
        if (njt_tolower(s->data[i]) == njt_tolower(txt[i])) {
            return 0;
        }
    }
    return 1;
}

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
                                                       arg->len) == 0) {
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
                                                && njt_memcmp(port, listen_port, p + arg->len - port) == 0)
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
                                        // TODO check LOCALhost ...
                                        if ( tmp_port != NJT_ERROR || tmp_listen_port != NJT_ERROR 
                                             || (arg->len >= 7 && njt_memcmp(arg->data, "0.0.0.0", 7)) == 0 
                                             || (listen->len >= 7 && njt_memcmp(listen->data, "0.0.0.0", 7)) == 0) 
                                        {
                                            addr_match = 1;
                                        } else { // 127.0.0.1 == localhost
                                            if (arg->len >= 9  && (njt_memcmp(p, "127.0.0.1", 9) == 0
                                                                  || njt_match_case_insensitive(arg, (u_char *)"localhost", 9) == 1)) {
                                                    localhost = 1;
                                            } 
                                            if (listen->len >= 9 && (njt_memcmp(listen->data, "localhost", 9) == 0 
                                                                   || njt_memcmp(listen->data, "127.0.0.1", 9) == 0)) {
                                                listen_localhost = 1;
                                            } 
                                            if (localhost == 0 && listen_localhost == 0) {
                                                if (port) {
                                                    if (((listen_port && port - p == listen_port - listen->data) || (size_t)(port - p) == listen->len) 
                                                        && njt_memcmp(arg->data, listen->data, port - p) == 0)
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

    if (block->cmds == NULL) {
        return 0;
    }

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

    if (cmd->key.len > 0 && cmd->key.data) {
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
                njt_pfree(pool, arg->data);
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
        // block->block_name = NULL;
    }

    if (block->cmds) {
        for (i = 0; i < block->cmds->nelts; i++) {
            cmd = &((njt_conf_cmd_t*)block->cmds->elts)[i];
            njt_conf_free_cmd(pool, cmd);
        }
        njt_pfree(pool, block->cmds->elts);
        // block->cmds = NULL;
    }

    if (block->blocks) {
        for (i = 0; i < block->blocks->nelts; i++) {
            sub_block = &((njt_conf_block_t *)block->blocks->elts)[i];
            njt_conf_free_block(pool, sub_block);
        }
        njt_pfree(pool, block->blocks->elts);
        // block->blocks = NULL;
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

    block->block_name = njt_pcalloc(pool, sizeof(njt_conf_cmd_t));
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

njt_int_t
njt_conf_add_cmd_full(njt_pool_t *pool, njt_conf_element_t *block, njt_conf_cmd_t *c) {
    njt_uint_t       i, j, found;
    njt_str_t       *name, *arg, *cur;
    njt_array_t     *args, *new_args, *tmp;
    njt_conf_cmd_t  *cmd;

    if (!block->cmds) {
        block->cmds = njt_array_create(pool, 1, sizeof(njt_conf_cmd_t));
        if (!block->cmds) {
            return NJT_ERROR;
        }
    }

    name = &c->key;
    found = 0;
    // 这里目前看是肯定没有这个命令的
    // for (i = 0; i < block->cmds->nelts; i++) {
    //     cmd = &((njt_conf_cmd_t *)(block->cmds->elts))[i];
    //     if (cmd->key.len != name->len) {
    //         continue;
    //     }

    //     // 这里之前用njt_strcmp出过错误，有时ccmd->key_data的len之后不是\0
    //     if (njt_memcmp(name->data, cmd->key.data, name->len) != 0) {
    //         continue;
    //     }

    //     found = 1;
    //     break;
    // }

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

    // 这里直接复制就可以，已经转义过了
    for (i = 0; i < c->value->nelts; i++) {
        args = &((njt_array_t *)c->value->elts)[i];
        new_args = njt_array_push(cmd->value);
        if (new_args == NULL) {
            return NJT_ERROR;
        }
        tmp = njt_array_create(pool, 1, sizeof(njt_str_t));
        njt_memcpy(new_args, tmp, sizeof(njt_array_t));
        njt_pfree(pool, tmp);
        for (j = 0; j < args->nelts; j++){
            arg = &((njt_str_t *)args->elts)[j];
            cur = njt_array_push(new_args);
            if (cur == NULL) {
                return NJT_ERROR;
            }
            cur->data = njt_palloc(pool, arg->len);
            if (cur->data == NULL) {
                return NJT_ERROR;
            }
            cur->len = arg->len;
            njt_memcpy(cur->data, arg->data, arg->len);
        }
    }
    return NJT_OK;
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
    // 检查http块是否存在，及http block下是否有block
    if (http == NULL || http->blocks == NULL) {
        return NJT_OK;
    }

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

    njt_destroy_pool(dyn_pool);
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
        if (block->key.len != key->len) {
            continue;
        }

        if (njt_memcmp(key->data, block->key.data, key->len) != 0) {
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
njt_conf_copy_block_name(njt_pool_t *pool, njt_conf_cmd_t *new, njt_conf_cmd_t *old) {
    njt_uint_t    i, j;
    njt_array_t *args, *new_args, *tmp;
    njt_str_t   *arg, *new_arg;


    new->value = njt_array_create(pool, 1, sizeof(njt_array_t));
    if (new->value == NULL) {
        return NJT_ERROR;
    }

    for (i = 0; i < old->value->nelts; i++) {
        args = &((njt_array_t *)old->value->elts)[i];
        new_args = njt_array_push(new->value);
        if (new_args == NULL) {
            return NJT_ERROR;
        }

        tmp = njt_array_create(pool, 1, sizeof(njt_str_t));
        if (tmp == NULL) {
            return NJT_ERROR;
        }
        njt_memcpy(new_args, tmp, sizeof(njt_array_t));
        njt_pfree(pool, tmp);


        for (j = 0; j < args->nelts; j++) {
            arg = &((njt_str_t *)args->elts)[i];
            new_arg = njt_array_push(new_args);
            if (new_arg == NULL) {
                return NJT_ERROR;
            }
            new_arg->data = njt_palloc(pool, arg->len);
            if (new_arg->data == NULL) {
                return NJT_ERROR;
            }
            njt_memcpy(new_arg->data, arg->data, arg->len);
            new_arg->len = arg->len;
        }
    }

    return NJT_OK;
}

njt_int_t
njt_conf_add_block_deep_copy( njt_pool_t *pool, njt_conf_element_t *parent, 
    njt_conf_element_t *child, njt_str_t *key) 
{
    njt_uint_t              i, j, found;
    njt_conf_block_t       *block, *sub_block;
    njt_conf_element_t     *bpos, *sub_child;
    njt_conf_cmd_t         *cmd;

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
        if (block->key.len != key->len) {
            continue;
        }

        if (njt_memcmp(key->data, block->key.data, key->len) != 0) {
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
    njt_memzero(bpos, sizeof(njt_conf_element_t));
    // cp block_name;
    if (child->block_name != NULL) {
        bpos->block_name = njt_pcalloc(pool, sizeof(njt_conf_cmd_t));
        if (bpos->block_name == NULL) {
            return NJT_ERROR;
        }
        if (njt_conf_copy_block_name(pool, bpos->block_name, child->block_name) != NJT_OK) {
            return NJT_ERROR;
        }
    }
    // cp cmds
    if (child->cmds != NULL) {
        for (i = 0; i < child->cmds->nelts; i++) {
            cmd = &((njt_conf_cmd_t *)child->cmds->elts)[i];
            if (njt_conf_add_cmd_full(pool, bpos, cmd) != NJT_OK) {
                return NJT_ERROR;
            }
        }
    }
    // cp blocks
    if (child->blocks != NULL) {
        for (i = 0; i < child->blocks->nelts; i++) {
            sub_block = &((njt_conf_block_t *)(child->blocks->elts))[i];
            for (j = 0; j < sub_block->value->nelts; j++) {
                sub_child = &((njt_conf_element_t *)(sub_block->value->elts))[i];
                if (njt_conf_add_block_deep_copy(pool, bpos, sub_child, &sub_block->key) != NJT_OK) {
                    return NJT_ERROR;
                }
            }
        }
    }
    
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

    if (njt_write_file(&file, out.data, out.len, 0) == NJT_ERROR) {
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

        if (root->cmds != NULL || (root->cmds == NULL && root->block_name)) {
            dst--;
        }

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
            if (j > 0) {
                dst--; // last ,
            }
            *dst++ = ']'; 
            out->len = dst - out->data;
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


#if NJT_HTTP_DYNAMIC_LOC
njt_int_t
njt_conf_dyn_loc_init_locs(njt_pool_t *pool, njt_conf_element_t *new, njt_conf_element_t *old) {
    njt_uint_t          i, j;
    njt_conf_element_t *loc; // , *new_loc;
    // njt_conf_cmd_t     *cmd;
    njt_conf_block_t   *block; //, *loc_block;

    if (old->blocks == NULL) {
        return NJT_OK;
    }
    for (i = 0; i < old->blocks->nelts; i++) {
        block = &((njt_conf_block_t*) old->blocks->elts)[i];
        // find server block
        if (block->key.len == 8 
            && njt_strncmp(block->key.data, "location", 8) == 0) 
        {
            // add new block to root->blocks
            // new->blocks = njt_array_create(pool, 1, sizeof(njt_conf_block_t));
            // if (!new->blocks) {
            //     return NJT_ERROR;
            // }
        
            // loc_block = njt_array_push(new->blocks);
            // loc_block->key.data = njt_palloc(pool, 8);
            // if (loc_block->key.data == NULL) {
            //     return NJT_ERROR;
            // }
            // njt_str_set(&loc_block->key, "location");
            // loc_block->value = njt_array_create(pool, 1, sizeof(njt_conf_element_t));

            // iterate locations
            for (j = 0; j < block->value->nelts; j++) {

                loc = &((njt_conf_element_t*)block->value->elts)[j];
                if (njt_conf_add_block_deep_copy(pool, new, loc, &block->key) != NJT_OK) {
                    return NJT_ERROR;
                };
                // create new location
                // new_loc = njt_array_push(loc_block->value);
                // if (new_loc == NULL) {
                //     return NJT_ERROR;
                // }
                // // copy block_name
                // new_loc->block_name = njt_pcalloc(pool, sizeof(njt_conf_cmd_t));
                // if (new_loc->block_name == NULL) {
                //     return NJT_ERROR;
                // }
                // cmd = new_loc->block_name;
                // if (njt_conf_copy_block_name(pool, cmd, loc->block_name) != NJT_OK) {
                //     return NJT_ERROR;
                // }

                // njt_conf_dyn_loc_init_locs(pool, new_loc, loc);
            }
        }
    }

    return NJT_OK;
}

njt_conf_element_t * njt_conf_dyn_loc_init_server(njt_pool_t *pool, njt_conf_element_t* conf_root) {
    njt_uint_t          i, j, k, cnt;
    njt_conf_element_t *root, *http, *svr, *new_svr;
    njt_conf_block_t   *block, *svr_block;
    njt_conf_cmd_t     *cmd;
    njt_pool_t         *dyn_pool;
    njt_str_t           s_http;


    // will be destroy at the end of func
    dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (dyn_pool == NULL) {
        return NULL;
    }

    // create a new njt_conf_element_t
    root = njt_pcalloc(pool, sizeof(njt_conf_element_t));
    if (root == NULL) {
        goto failed;
    }

    // find http
    s_http.data = njt_palloc(dyn_pool, 4);
    if(s_http.data == NULL) {
       goto failed;
    }
    njt_str_set(&s_http, "http");

    http = njt_conf_get_block(conf_root, &s_http, NULL);
    // http = njt_conf_get_block(njt_cycle->conf_root, &s_http, NULL);
    if (http == NULL) {
        goto failed;
    }

    if (http->blocks == NULL) {
        njt_destroy_pool(dyn_pool);
        return root;
    }

    for (i = 0; i < http->blocks->nelts; i++) {
        block = &((njt_conf_block_t*)http->blocks->elts)[i];
        // find server block
        if (block->key.len == 6 
            && njt_strncmp(block->key.data, "server", 6) == 0) 
        {
            // add new block to root->blocks
            root->blocks = njt_array_create(pool, 1, sizeof(njt_conf_block_t));
            if (!root->blocks) {
                goto failed;
            }
            
            svr_block = njt_array_push(root->blocks);
            svr_block->key.data = njt_palloc(pool, 6);
            if (svr_block->key.data == NULL) {
                goto failed;
            }
            njt_str_set(&svr_block->key, "server");
            svr_block->value = njt_array_create(pool, 1, sizeof(njt_conf_element_t));


            // iterate server
            for (j = 0; j < block->value->nelts; j++) {

                svr = &((njt_conf_element_t*)block->value->elts)[j];
                // create new server
                new_svr = njt_array_push(svr_block->value);
                if (new_svr == NULL) {
                    goto failed;
                }
                njt_memset(new_svr, 0, sizeof(njt_conf_element_t));

                for (k = 0; k < svr->cmds->nelts; k++) { // no need to check null
                    cnt = 0;
                    // cmd = &((njt_conf_cmd_t *)svr->cmds->elts)[k];
                    cmd = &((njt_conf_cmd_t *)svr->cmds->elts)[k];
                    // printf("key: %s \n", cmd->key.data);
                    if (cmd->key.len == 6 && njt_strncmp(cmd->key.data, "listen", 6) == 0) {
                        njt_conf_add_cmd_full(pool, new_svr, cmd); // 增加一个函数，add_cmd_full
                        cnt++;
                    };
                    if (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server_name", 11) == 0) {
                        njt_conf_add_cmd_full(pool, new_svr, cmd); // 增加一个函数，add_cmd_full
                        cnt++;
                    }
                    if (cnt == 2) { // 只记录这两个命令的值
                        break;
                    }
                }
                njt_conf_dyn_loc_init_locs(pool, new_svr, svr);
            }
        }
    }

    // del block is added on dyn_loc del handler
    njt_destroy_pool(dyn_pool);
    return root;

failed:
    njt_destroy_pool(dyn_pool);
    return NULL;
}

njt_int_t 
njt_conf_dyn_loc_add_sub_loc(njt_pool_t *pool, njt_conf_element_t *block, 
                             njt_conf_sub_location_info_t *loc_info) 
{
    njt_uint_t                   i;
    njt_str_t                    full_name, *arg;
    njt_str_t                    s_loc, s_rule, s_loc_name, s_body, s_pass;
    njt_pool_t                   *dyn_pool;
    njt_array_t                  *cf;
    njt_conf_element_t           *loc;
    u_char                       *p;
    njt_conf_sub_location_info_t *sub_loc;
    
    dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (dyn_pool == NULL) {
        return NJT_ERROR;
    }

    full_name.data = njt_palloc(dyn_pool, 1024);
    if (full_name.data == NULL) {
        return NJT_ERROR;
    }

    s_rule.data = njt_palloc(dyn_pool, 12);
    if (s_rule.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_rule, "location_rule");

    s_loc_name.data = njt_palloc(dyn_pool, 12);
    if (s_loc_name.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_loc_name, "location_name");

    s_body.data = njt_palloc(dyn_pool, 12);
    if (s_body.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_body, "location_body");

    s_loc.data = njt_palloc(dyn_pool, 7);
    if (s_loc.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_loc, "location");

    s_pass.data = njt_palloc(dyn_pool, 9);
    if (s_pass.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_pass, "proxy_pass");


    if (loc_info->location_rule.len > 0) {
        p = njt_snprintf(full_name.data, 1023, "%V%V", &loc_info->location_rule, &loc_info->location);
    } else {
        p = njt_snprintf(full_name.data, 1023, "%V", &loc_info->location);
    }
    full_name.len = p - full_name.data;

    loc = njt_conf_get_simple_location_block(pool, block, &full_name);
        
    if (loc == NULL) {
        njt_destroy_pool(dyn_pool);
        // printf("error, should have location \n");
        return NJT_ERROR;
    } else {
        // loc = njt_pcalloc(pool, sizeof(njt_conf_element_t));
    }

    // add block name "_key"
    cf = njt_array_create(dyn_pool, 1, sizeof(njt_str_t));
    if (cf == NULL) {
        return NJT_ERROR;
    }
    arg = njt_array_push(cf);
    arg->len = 0; // first is the cmd name
    arg = njt_array_push(cf);
    arg->data = full_name.data;
    arg->len = full_name.len;

    loc->block_name = njt_pcalloc(pool, sizeof(njt_command_t));
    if (loc->block_name == NULL) {
        return NJT_ERROR;
    }
    loc->block_name->value = njt_array_create(pool, 1, sizeof(njt_array_t));
    if (loc->block_name->value == NULL) {
        return NJT_ERROR;
    }
    if (njt_conf_cmd_set_value(pool, loc->block_name, cf) != NJT_OK) {
        return NJT_ERROR;
    }

    // add location_rule
    cf = njt_array_create(dyn_pool, 1, sizeof(njt_str_t));
    if (cf == NULL) {
        return NJT_ERROR;
    }
    arg = njt_array_push(cf);
    njt_memcpy(arg, &s_rule, sizeof(njt_str_t));
    if (loc_info->location_rule.len > 0) {
        arg = njt_array_push(cf);
        njt_memcpy(arg, &loc_info->location_rule, sizeof(njt_str_t));
    }
    if (njt_conf_add_cmd(pool, loc, cf) != NJT_OK) {
        return NJT_ERROR;
    }

    // add location_name
    cf = njt_array_create(dyn_pool, 1, sizeof(njt_str_t));
    if (cf == NULL) {
        return NJT_ERROR;
    }
    arg = njt_array_push(cf);
    njt_memcpy(arg, &s_loc_name, sizeof(njt_str_t));
    arg = njt_array_push(cf);
    njt_memcpy(arg, &loc_info->location, sizeof(njt_str_t));
    if (njt_conf_add_cmd(pool, loc, cf) != NJT_OK) {
        return NJT_ERROR;
    }


    // add proxy_pass 
    if (loc_info->proxy_pass.len > 0) {
        cf = njt_array_create(dyn_pool, 1, sizeof(njt_str_t));
        if (cf == NULL) {
            return NJT_ERROR;
        }
        arg = njt_array_push(cf);
        njt_memcpy(arg, &s_pass, sizeof(njt_str_t));
        arg = njt_array_push(cf);
        njt_memcpy(arg, &loc_info->proxy_pass, sizeof(njt_str_t));
        if ( njt_conf_add_cmd(pool, loc, cf) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    // add location_body
    if (loc_info->location_body.len > 0 ) {
        cf = njt_array_create(dyn_pool, 1, sizeof(njt_str_t));
        if (cf == NULL) {
            return NJT_ERROR;
        }
        arg = njt_array_push(cf);
        njt_memcpy(arg, &s_body, sizeof(njt_str_t));
        arg = njt_array_push(cf);
        njt_memcpy(arg, &loc_info->location_body, sizeof(njt_str_t));
        if (njt_conf_add_cmd(pool, loc, cf) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (loc_info->sub_location_array != NULL) {
        for (i = 0; i < loc_info->sub_location_array->nelts; i++) {
            sub_loc = &((njt_conf_sub_location_info_t *)loc_info->sub_location_array->elts)[i];
            if (njt_conf_dyn_loc_add_sub_loc(pool, loc, sub_loc) != NJT_OK) {
                return NJT_ERROR;
            }
        }
    }
    njt_destroy_pool(dyn_pool);


    return NJT_OK;
}

njt_int_t
njt_conf_dyn_loc_add_loc(njt_pool_t *pool, njt_conf_element_t *root, njt_conf_location_info_t *loc_info) {
    njt_uint_t                   i; // , j;
    njt_conf_element_t           *svr; //, *del;
    njt_array_t                  *cf;
    njt_str_t                     s_type, s_add, s_del, s_port, s_svr_name, *arg, s_rule, s_loc_name;
    // njt_str_t                    *rule, *lname;
    njt_pool_t                   *dyn_pool;
    njt_conf_sub_location_info_t *sub_loc;
    // njt_conf_block_t             *del_block;
    // njt_conf_cmd_t               *cmd;
    

    dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (dyn_pool == NULL) {
        return NJT_ERROR;
    }

    s_type.data = njt_palloc(dyn_pool, 4);
    if (s_type.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_type, "type");

    s_add.data = njt_palloc(dyn_pool, 3);
    if (s_add.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_add, "add");

    s_del.data = njt_palloc(dyn_pool, 3);
    if (s_del.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_del, "del");

    s_svr_name.data = njt_palloc(dyn_pool, 11);
    if (s_svr_name.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_svr_name, "server-name");

    s_port.data = njt_palloc(dyn_pool, 9);
    if (s_port.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_port, "addr_port");

    s_rule.data = njt_palloc(dyn_pool, 13);
    if (s_rule.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_rule, "location_rule");

    s_loc_name.data = njt_palloc(dyn_pool, 13);
    if (s_loc_name.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_loc_name, "location_name");

    // check type == "add"


    // find server first
    svr = njt_conf_get_server_block(root, &loc_info->addr_port, &loc_info->server_name);
    if (svr == NULL) {
        return NJT_ERROR;
    }

    // add type -> add; 
    if (njt_conf_get_cmd_conf(svr, &s_type) == NULL) {
        cf = njt_array_create(dyn_pool, 2, sizeof(njt_str_t));
        if (cf == NULL) {
            return NJT_ERROR;
        }
        arg = njt_array_push(cf);
        njt_memcpy(arg, &s_type, sizeof(njt_str_t));
        arg = njt_array_push(cf);
        njt_memcpy(arg, &s_add, sizeof(njt_str_t));

        if (njt_conf_set_cmd(pool, svr, cf) != NJT_OK) {
            return NJT_ERROR;
        }

        // add addr_port;
        cf = njt_array_create(dyn_pool, 2, sizeof(njt_str_t));
        if (cf == NULL) {
            return NJT_ERROR;
        }
        arg = njt_array_push(cf);
        njt_memcpy(arg, &s_port, sizeof(njt_str_t));
        arg = njt_array_push(cf);
        njt_memcpy(arg, &loc_info->addr_port, sizeof(njt_str_t));

        if (njt_conf_set_cmd(pool, svr, cf) != NJT_OK) {
            return NJT_ERROR;
        }
        // add server-name;
        cf = njt_array_create(dyn_pool, 2, sizeof(njt_str_t));
        if (cf == NULL) {
            return NJT_ERROR;
        }
        arg = njt_array_push(cf);
        njt_memcpy(arg, &s_svr_name, sizeof(njt_str_t));
        arg = njt_array_push(cf);
        njt_memcpy(arg, &loc_info->server_name, sizeof(njt_str_t));

        if (njt_conf_set_cmd(pool, svr, cf) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    // for each location 
    for (i = 0; i < loc_info->location_array->nelts; i++) {

        sub_loc = &((njt_conf_sub_location_info_t *)loc_info->location_array->elts)[i]; 
        if (njt_conf_dyn_loc_add_sub_loc(pool, svr, sub_loc) != NJT_OK) {
            return NJT_ERROR;
        };

        // rm from del, root only have at_most two blocks, server, del
        // if (root->blocks->nelts == 1) {
        //     continue;
        // }

        // for(j = 0; j < root->blocks->nelts; j++) {
        //     del_block = &((njt_conf_block_t *)root->blocks->elts)[j];
        //     if (del_block->key.len == 3) {
        //         break;
        //     }
        // }

        // for (j = 0; j < del_block->value->nelts; j++) {
        //     del = &((njt_conf_element_t *)del_block->value->elts)[j];
        //     cmd = njt_conf_get_cmd_conf(del, &s_rule);
        //     if (cmd == NULL) {
        //         return NJT_ERROR;
        //     }
        //     cf = cmd->value->elts; // array[0]
        //     rule = cf->elts; // array[0] value of  addr_port

        //     cmd = njt_conf_get_cmd_conf(del, &s_loc_name);
        //     if (cmd == NULL) {
        //         return NJT_ERROR;
        //     }
        //     cf = cmd->value->elts; // array[0]
        //     lname = cf->elts; // array[0] value of server_name

        //     if ((sub_loc->location_rule.len == rule->len && njt_strncmp(sub_loc->location_rule.data, rule->data, rule->len) == 0)
        //         && (sub_loc->location.len == lname->len && njt_strncmp(sub_loc->location.data, lname->data, lname->len) == 0))
        //     {
        //         njt_conf_delete_block(pool, del);   
        //         break;
        //     }
        // }
    }

    njt_destroy_pool(dyn_pool);
    return NJT_OK;
}


njt_int_t njt_conf_dyn_loc_del_loc(njt_pool_t * pool, njt_conf_element_t *root, njt_conf_location_info_t *loc_info) {
    njt_conf_element_t           *svr, *loc; // , *child;
    njt_str_t                   full_name, loc_full_name; // , *arg;
    // njt_str_t                    s_port, s_rule, s_loc_name, s_svr_name, s_type, s_del;
    u_char                      *p;
    njt_pool_t                  *dyn_pool;
    // njt_array_t                 *cf;
    

    dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (dyn_pool == NULL) {
        return NJT_ERROR;
    }

    // check type == "del"

    // find server first
    svr = njt_conf_get_server_block(root, &loc_info->addr_port, &loc_info->server_name);
    if (svr == NULL) {
        return NJT_ERROR;
    }

    full_name.data = njt_palloc(dyn_pool, 1024);
    if (full_name.data == NULL) {
        return NJT_ERROR;
    }

    if (loc_info->location_rule.len > 0 ) {
        p = njt_snprintf(full_name.data, 1024, "%V%V", &loc_info->location_rule, &loc_info->location);
    } else {
        p = njt_snprintf(full_name.data, 1024, "%V", &loc_info->location);
    }
    full_name.len = p - full_name.data;
    loc_full_name = add_escape(dyn_pool, full_name);

    printf("del loc full name: %s\n", loc_full_name.data);
    loc = njt_conf_get_simple_location_block(dyn_pool, svr, &loc_full_name);
    if (loc == NULL) {
        njt_destroy_pool(dyn_pool);
        return NJT_OK;
    }

    // rm from svr.location
    if (njt_conf_delete_block(pool, loc) != NJT_OK) {
        return NJT_ERROR;
    }

    // child = njt_pcalloc(pool, sizeof(njt_conf_element_t));
    // if (child == NULL) {
    //     return NJT_ERROR;
    // }

    // s_rule.data = njt_palloc(dyn_pool, 13);
    // if (s_rule.data == NULL) {
    //     return NJT_ERROR;
    // }
    // njt_str_set(&s_rule, "location_rule");

    // s_loc_name.data = njt_palloc(dyn_pool, 13);
    // if (s_loc_name.data == NULL) {
    //     return NJT_ERROR;
    // }
    // njt_str_set(&s_loc_name, "location_name");

    // s_svr_name.data = njt_palloc(dyn_pool, 11);
    // if (s_svr_name.data == NULL) {
    //     return NJT_ERROR;
    // }
    // njt_str_set(&s_svr_name, "server_name");

    // s_port.data = njt_palloc(dyn_pool, 9);
    // if (s_port.data == NULL) {
    //     return NJT_ERROR;
    // }
    // njt_str_set(&s_port, "addr_port");

    // s_type.data = njt_palloc(dyn_pool, 4);
    // if (s_type.data == NULL) {
    //     return NJT_ERROR;
    // }
    // njt_str_set(&s_type, "type");

    // s_del.data = njt_palloc(dyn_pool, 3);
    // if (s_del.data == NULL) {
    //     return NJT_ERROR;
    // }
    // njt_str_set(&s_del, "del");

    // // add type -> del
    // cf = njt_array_create(dyn_pool, 2, sizeof(njt_str_t));
    // if (cf == NULL) {
    //     return NJT_ERROR;
    // }
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &s_type, sizeof(njt_str_t));
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &s_del, sizeof(njt_str_t));
    // if (njt_conf_add_cmd(pool, child, cf) != NJT_OK) {
    //     return NJT_ERROR;
    // }

    // // add location_rule
    // cf = njt_array_create(dyn_pool, 2, sizeof(njt_str_t));
    // if (cf == NULL) {
    //     return NJT_ERROR;
    // }
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &s_rule, sizeof(njt_str_t));
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &loc_info->location_rule, sizeof(njt_str_t));
    // if (njt_conf_add_cmd(pool, child, cf) != NJT_OK) {
    //     return NJT_ERROR;
    // }

    // // add location_name
    // cf = njt_array_create(dyn_pool, 2, sizeof(njt_str_t));
    // if (cf == NULL) {
    //     return NJT_ERROR;
    // }
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &s_loc_name, sizeof(njt_str_t));
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &loc_info->location, sizeof(njt_str_t));
    // if (njt_conf_add_cmd(pool, child, cf) != NJT_OK) {
    //     return NJT_ERROR;
    // }


    // // add addr_port 
    // cf = njt_array_create(dyn_pool, 2, sizeof(njt_str_t));
    // if (cf == NULL) {
    //     return NJT_ERROR;
    // }
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &s_port, sizeof(njt_str_t));
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &loc_info->addr_port, sizeof(njt_str_t));
    // if (njt_conf_add_cmd(pool, child, cf) != NJT_OK) {
    //     return NJT_ERROR;
    // }

    // // add svr_name
    // cf = njt_array_create(dyn_pool, 2, sizeof(njt_str_t));
    // if (cf == NULL) {
    //     return NJT_ERROR;
    // }
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &s_svr_name, sizeof(njt_str_t));
    // arg = njt_array_push(cf);
    // njt_memcpy(arg, &loc_info->server_name, sizeof(njt_str_t));
    // if (njt_conf_add_cmd(pool, child, cf) != NJT_OK) {
    //     return NJT_ERROR;
    // }

    // if (njt_conf_add_block(pool, root, child, &s_del) != NJT_OK) {
    //     return NJT_ERROR;
    // }



    njt_destroy_pool(dyn_pool);
    return NJT_OK;
}


njt_uint_t njt_conf_dyn_loc_has_dyn_loc(njt_conf_element_t *root) {
    njt_uint_t          i;
    njt_conf_block_t   *block;
    njt_conf_element_t *loc;
    njt_str_t           s_loc_name;
    njt_pool_t         *dyn_pool;

    if (root == NULL) {
        return 0;
    }

    dyn_pool = njt_create_pool(1024, njt_cycle->log);
    s_loc_name.data = njt_palloc(dyn_pool, 13);
    if (s_loc_name.data == NULL) {
        njt_destroy_pool(dyn_pool);
        return 0;
    }
    njt_str_set(&s_loc_name, "location_name");
    
    if (root->blocks != NULL) { // must has only one block in blocks
        block = root->blocks->elts;
        for (i = 0; i < block->value->nelts; i++) {
            loc = &((njt_conf_element_t *)block->value->elts)[i];
            if (njt_conf_dyn_loc_has_dyn_loc(loc) == 1) {
                njt_destroy_pool(dyn_pool);
                return 1;
            }
        }
    }

    i = njt_conf_get_cmd_conf(root, &s_loc_name) == NULL ? 0 : 1;

    njt_destroy_pool(dyn_pool);
    return i;


}

njt_int_t 
njt_conf_dyn_loc_merge_location(njt_pool_t *pool, njt_str_t* addr_port, njt_str_t *svr_name, njt_conf_element_t* dyn_locs) {
    njt_uint_t          i, j, len;
    njt_str_t           s_loc, s_fullname, *arg;
    njt_array_t        *args;
    njt_conf_element_t *loc, *svr, *old_loc; 
    njt_conf_block_t   *block;
    njt_pool_t         *dyn_pool;

    if (dyn_locs->blocks == NULL) {
        return NJT_OK;
    }

    dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (dyn_pool == NULL) {
        return NJT_ERROR;
    }

    svr = njt_conf_get_server_block(njt_conf_dyn_loc_ptr, addr_port, svr_name);
    if (svr == NULL) {
        return NJT_OK;
    }

    s_loc.data = njt_palloc(dyn_pool, 8);
    if (s_loc.data == NULL) {
        return NJT_ERROR;
    }
    njt_str_set(&s_loc, "location");

    block = dyn_locs->blocks->elts; // only has one block -> location: [...]
    if (block->key.len != 8 || njt_memcmp(block->key.data, s_loc.data, 8) != 0) {
        njt_pfree(pool, s_loc.data);
        return NJT_ERROR;
    }

    for (i = 0; i < block->value->nelts; i++) {
        loc = &((njt_conf_element_t *)block->value->elts)[i];

        len = 0;
        args = loc->block_name->value->elts; // location->block_name->value->nelts must eq to 1
        for (j = 0; j < args->nelts; j++) {
            arg = &((njt_str_t *)args->elts)[i];
            len += arg->len;
        }
        s_fullname.data = njt_palloc(dyn_pool, len);
        if (s_fullname.data == NULL) {
            goto failed;
        }
        s_fullname.len = 0;
        for (j = 0; j < args->nelts; j++) {
            arg = &((njt_str_t *)args->elts)[i];
            if (arg->len == 0) {
                continue;
            }
            njt_sprintf(s_fullname.data + s_fullname.len, "%V", arg);
            s_fullname.len += arg->len;
        }

        printf("s_fullname: %s\n", s_fullname.data);
        // TODO 如果以后允许嵌套增加dyn_loc， 这里逻辑要改成递归的
        old_loc = njt_conf_get_simple_location_block(dyn_pool, svr, &s_fullname);
        if (old_loc != NULL) {
            if (njt_conf_delete_block(pool, old_loc) != NJT_OK) {
                goto failed;
            }
        }
        if (njt_conf_add_block(pool, svr, loc, &s_loc) != NJT_OK) {
            goto failed;
        }
    }

    return NJT_OK;

failed:
    njt_destroy_pool(dyn_pool);
    return NJT_ERROR;
}


void njt_conf_dyn_loc_get_json_length(njt_conf_element_t *root, size_t *length, njt_uint_t is_root) {
    njt_uint_t               i, j, k, cnt;
    njt_conf_cmd_t          *cmd;
    njt_array_t             *values;
    njt_str_t               *arg;
    njt_conf_block_t        *blocks;
    njt_conf_element_t      *block;
    njt_uint_t               is_svr, is_loc, omit; 

    *length += 1;

    if(root == NULL) {
        return;
    }

    // all blocks doesn't need "_key"
    // if (root->block_name != NULL) {
    //     *length += 7; // "_key":  "block_name",
    //     cmd = root->block_name;
    //     if (cmd->value->nelts == 1) {
    //         // "key": "value",
    //         values = cmd->value->elts;
    //         if (values->nelts == 1) {
    //             // all as string now, change to boolean or number later
    //             arg = (njt_str_t*)values->elts;// "key": "value",
    //             *length += arg->len + 2;
    //         } else {
    //             *length += 1; 
    //             for (k = 0; k < values->nelts; k++) {
    //                 arg = &((njt_str_t*)values->elts)[k];
    //                 *length += arg->len + 3;
    //             }
    //         }
    //     }
    //     *length += 1; 
    // }
      

    if (root->cmds) {
        for (i = 0; i < root->cmds->nelts; i++) {
            cmd = &((njt_conf_cmd_t *)root->cmds->elts)[i];
            omit = 1;
            omit = (cmd->key.len == 4 && njt_strncmp(cmd->key.data, "type", 4) == 0) ? 0 : 1; 
            if (omit == 1) {
                omit = (cmd->key.len == 8 && njt_strncmp(cmd->key.data, "location", 8) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 9 && njt_strncmp(cmd->key.data, "addr_port", 9) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server-name", 11) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_rule", 13) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_body", 13) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_name", 13) == 0) ? 0 : 1; 
            }
            if (omit) {
                continue;
            }

            *length += cmd->key.len + 3;
            // printf("key: %s \n", cmd->key.data);
            if (cmd->value->nelts == 1) {
                // "key": "value",
                values = cmd->value->elts;
                if (values->nelts == 1) {
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
        if (root->cmds == NULL && root->block_name == NULL) {
            *length += 1;
        }
        return;
    }

    for (i = 0; i < root->blocks->nelts; i++) {
        blocks = &((njt_conf_block_t*)root->blocks->elts)[i];
        is_svr = (blocks->key.len == 6 && njt_strncmp(blocks->key.data, "server", 6) == 0);
        is_loc = (blocks->key.len == 8 && njt_strncmp(blocks->key.data, "location", 8) == 0);
        *length += is_loc ? blocks->key.len + 3 + 1 : 0; // location -> locations
        // if (blocks->value->nelts == 1 && !(is_loc || is_svr)) {
        //     block = blocks->value->elts; // http : {}
        //     njt_conf_dyn_loc_get_json_length(block, length, 0);
        // } else { // locaction [{location1}, {location2}, ...]
            *length += 1;
            cnt = 0;
            for (j = 0; j < blocks->value->nelts; j++) {
                block = &((njt_conf_element_t*)blocks->value->elts)[j];
                if ((is_svr || is_loc) && njt_conf_dyn_loc_has_dyn_loc(block) == 0) {
                    continue;
                }
                cnt ++;
                njt_conf_dyn_loc_get_json_length(block, length, 0);
                *length += 1;
            }
            if (cnt == 0) {
                *length += 1;
            }
        // }
        *length += 1;
    }
}

void 
njt_conf_dyn_loc_get_json_str(njt_conf_element_t *root, njt_str_t *out, njt_uint_t is_root)
{
    njt_uint_t             i, j, k, cnt, omit;
    njt_uint_t             is_svr, is_loc, is_svr_name;
    njt_conf_cmd_t        *cmd;
    njt_array_t           *values;
    njt_str_t             *arg;
    njt_conf_block_t      *blocks;
    njt_conf_element_t    *block;
    u_char *dst;


    dst = out->data + out->len;
    if (is_root) {
        *dst++ = '['; out->len++;
    } else {
        *dst++ = '{'; out->len++;
    }

    // if (root->block_name != NULL) {
    //     dst = njt_sprintf(dst, "\"_key\":"); //"_key":  "block_name",
    //     cmd = root->block_name;
    //     if (cmd->value->nelts == 1) {
    //         // "key": "value",
    //         values = cmd->value->elts;
    //         if (values->nelts == 1) {
    //             // all as string now, change to boolean or number later
    //             arg = (njt_str_t*)values->elts;// "key": "value",
    //             dst = njt_sprintf(dst, "\"%V\"", arg);
    //         } else {
    //             *dst++ = '['; 
    //             for (k = 0; k < values->nelts; k++) {
    //                 arg = &((njt_str_t*)values->elts)[k];
    //                 dst = njt_sprintf(dst, "\"%V\",", arg);
    //             }
    //             dst--; // last ,
    //             *dst++ = ']'; 
    //         }
    //     }
    //     *dst++ = ','; 
    // }

    if (root->cmds) {
        for (i = 0; i < root->cmds->nelts; i++) {
            cmd = &((njt_conf_cmd_t*)root->cmds->elts)[i];
            omit = 1;
            omit = (cmd->key.len == 4 && njt_strncmp(cmd->key.data, "type", 4) == 0) ? 0 : 1; 
            if (omit == 1) {
                omit = (cmd->key.len == 8 && njt_strncmp(cmd->key.data, "location", 8) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 9 && njt_strncmp(cmd->key.data, "addr_port", 9) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server-name", 11) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_rule", 13) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_body", 13) == 0) ? 0 : 1; 
            }
            if (omit == 1) {
                omit = (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_name", 13) == 0) ? 0 : 1; 
            }
            if (omit) {
                continue;
            }

            is_svr_name = (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server-name", 11) == 0);
            if (is_svr_name) {
                dst = njt_sprintf(dst, "\"server_name\":");
            } else {
                dst = njt_sprintf(dst, "\"%V\":", &cmd->key); // "key":
            }
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

        if (root->cmds != NULL || (root->cmds == NULL && root->block_name)) {
            dst--;
        }

        *dst++ = '}'; 
        out->len = dst - out->data;
        return;
    }

    for (i = 0; i < root->blocks->nelts; i++) {
        dst = out->data + out->len;
        blocks = &((njt_conf_block_t*)root->blocks->elts)[i];
        is_svr = (blocks->key.len == 6 && njt_strncmp(blocks->key.data, "server", 6) == 0);
        is_loc = (blocks->key.len == 8 && njt_strncmp(blocks->key.data, "location", 8) == 0);
        if (is_loc) {
            dst = njt_sprintf(dst, "\"locations\":"); // location -> locations
        } else {
            // dst = njt_sprintf(dst, "\"%V\":", &blocks->key); // "key":
        }
        out->len = dst - out->data;
        // if (blocks->value->nelts == 1 && !(is_svr || is_loc)) {
        //     // http : {}
        //     block = blocks->value->elts;
        //     njt_conf_get_json_str(block, out, 0);
        // } else {
            if (is_loc) {
                *dst++ = '['; 
                out->len = dst - out->data;
            }
            cnt = 0;
            for (j = 0; j < blocks->value->nelts; j++) {
                block = &((njt_conf_element_t*)blocks->value->elts)[j];
                if ((is_svr || is_loc) && njt_conf_dyn_loc_has_dyn_loc(block) == 0) { // new dyn location can only be added under server
                    continue;
                }
                cnt ++;
                njt_conf_dyn_loc_get_json_str(block, out, 0);
                dst = out->data + out->len;
                *dst++ = ','; 
                out->len = dst - out->data;
            }
            dst = out->data + out->len;
            if (cnt > 0) {
                dst--; // last ,
            }
            if (is_loc) {
                *dst++ = ']';
            } 
            out->len = dst - out->data;
        // }
        dst = out->data + out->len;
        if(cnt > 0) {
            *dst++ = ','; 
        }
        out->len = dst - out->data;
    }
    
    dst = out->data + out->len;
    if (out->len > 1) { // in case of []
        dst--;
    }

    if (is_root) {
        *dst++ = ']';
    } else {
        *dst++ = '}'; 
    }
    out->len = dst - out->data;
}

void njt_conf_dyn_loc_get_pub_json_length(njt_conf_element_t *root, size_t *length, njt_uint_t is_root) {
    njt_uint_t               i, j, k, omit;
    njt_conf_cmd_t          *cmd;
    njt_array_t             *values;
    njt_str_t               *arg;
    njt_conf_block_t        *blocks;
    njt_conf_element_t      *block;
    njt_uint_t               svr_or_loc, sname, listen; 

    if(root == NULL) {
        return;
    }

    *length += 1;

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
            listen = (cmd->key.len == 6 && njt_strncmp(cmd->key.data, "listen", 6) == 0);
            sname = (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server_name", 11) == 0);
            // printf("key: %s \n", cmd->key.data);

            omit = 0;
            omit += (cmd->key.len == 4 && njt_strncmp(cmd->key.data, "type", 4) == 0) ? 1 : 0; 
            if (omit == 0) {
                omit += (cmd->key.len == 8 && njt_strncmp(cmd->key.data, "location", 8) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 9 && njt_strncmp(cmd->key.data, "addr_port", 9) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server-name", 11) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_rule", 13) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_body", 13) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_name", 13) == 0) ? 1 : 0; 
            }
            if (omit) {
                continue;
            }

            *length += cmd->key.len + 3;

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
        if (root->cmds == NULL && root->block_name == NULL) {
            *length += 1;
        }
        return;
    }

    for (i = 0; i < root->blocks->nelts; i++) {
        blocks = &((njt_conf_block_t*)root->blocks->elts)[i];
        *length += blocks->key.len + 3;
        svr_or_loc = (blocks->key.len == 6 && njt_strncmp(blocks->key.data, "server", 6) == 0)
                     || (blocks->key.len == 8 && njt_strncmp(blocks->key.data, "location", 8) == 0);
        if (blocks->value->nelts == 1 && !svr_or_loc) {
            block = blocks->value->elts; // http : {}
            njt_conf_dyn_loc_get_pub_json_length(block, length, 0);
        } else { // locaction [{location1}, {location2}, ...]
            *length += 1;
            for (j = 0; j < blocks->value->nelts; j++) {
                block = &((njt_conf_element_t*)blocks->value->elts)[j];
                njt_conf_dyn_loc_get_pub_json_length(block, length, 0);
                *length += 1;
            }
            if (j == 0) {
                *length += 1;
            }
        }
        *length += 1;
    }
}

void 
njt_conf_dyn_loc_get_pub_json_str(njt_conf_element_t *root, njt_str_t *out, njt_uint_t is_root)
{
    njt_uint_t             i, j, k, omit;
    njt_uint_t             svr_or_loc, sname, listen;
    njt_conf_cmd_t        *cmd;
    njt_array_t           *values;
    njt_str_t             *arg;
    njt_conf_block_t      *blocks;
    njt_conf_element_t    *block;
    u_char *dst;

    if (root == NULL) {
        return;
    }

    dst = out->data + out->len;
    *dst++ = '{';
    out->len++;

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
            listen = (cmd->key.len == 6 && njt_strncmp(cmd->key.data, "listen", 6) == 0);
            sname = (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server_name", 11) == 0);

            omit = 0;
            omit += (cmd->key.len == 4 && njt_strncmp(cmd->key.data, "type", 4) == 0) ? 1 : 0; 
            if (omit == 0) {
                omit += (cmd->key.len == 8 && njt_strncmp(cmd->key.data, "location", 8) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 9 && njt_strncmp(cmd->key.data, "addr_port", 9) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 11 && njt_strncmp(cmd->key.data, "server-name", 11) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_rule", 13) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_body", 13) == 0) ? 1 : 0; 
            }
            if (omit == 0) {
                omit += (cmd->key.len == 13 && njt_strncmp(cmd->key.data, "location_name", 13) == 0) ? 1 : 0; 
            }
            if (omit) {
                continue;
            }

            dst = njt_sprintf(dst, "\"%V\":", &cmd->key); // "key":

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

        if (root->cmds != NULL || (root->cmds == NULL && root->block_name)) {
            dst--;
        }

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
            njt_conf_dyn_loc_get_pub_json_str(block, out, 0);
        } else {
            *dst++ = '['; 
            out->len = dst - out->data;
            for (j = 0; j < blocks->value->nelts; j++) {
                block = &((njt_conf_element_t*)blocks->value->elts)[j];
                njt_conf_dyn_loc_get_pub_json_str(block, out, 0);
                dst = out->data + out->len;
                *dst++ = ','; 
                out->len = dst - out->data;
            }
            dst = out->data + out->len;
            if (j > 0) {
                dst--; // last ,
            }
            *dst++ = ']'; 
            out->len = dst - out->data;
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

njt_str_t* njt_conf_dyn_loc_get_ins_str(njt_pool_t *pool, njt_conf_element_t *root) {
    size_t     length;
    njt_str_t *out;

    length = 0;
    njt_conf_dyn_loc_get_json_length(root, &length, 1);

    out = njt_pcalloc(pool, sizeof(njt_str_t));
    if (out == NULL) {
        return NULL;
    }
    out->data = njt_pcalloc(pool, length + 1);
    if (out->data == NULL) {
        return NULL;
    }

    njt_conf_dyn_loc_get_json_str(root, out, 1);

    return out;
}

njt_str_t* njt_conf_dyn_loc_get_pub_str(njt_pool_t *pool, njt_conf_element_t *root) {
    size_t     length;
    njt_str_t *out;

    length = 0;
    njt_conf_dyn_loc_get_pub_json_length(root, &length, 1);

    out = njt_pcalloc(pool, sizeof(njt_str_t));
    if (out == NULL) {
        return NULL;
    }
    out->data = njt_pcalloc(pool, length + 1);
    if (out->data == NULL) {
        return NULL;
    }

    njt_conf_dyn_loc_get_pub_json_str(root, out, 1);

    return out;
}


njt_conf_location_info_t* get_test_location_info(njt_pool_t *pool, njt_uint_t add) {
    njt_conf_location_info_t     *ret;
    njt_conf_sub_location_info_t *loc; // , *sub_loc;

    ret = njt_pcalloc(pool, sizeof(njt_conf_location_info_t));
    ret->addr_port.data = njt_palloc(pool, 12);
    njt_str_set(&ret->addr_port, "0.0.0.0:7323");
    ret->server_name.data = njt_palloc(pool, 5);
    njt_str_set(&ret->server_name, "testY");
    if (add) {
        ret->type.data = njt_palloc(pool, 3);
        njt_str_set(&ret->type, "add");
        ret->location_array = njt_array_create(njt_cycle->pool, 1, sizeof(njt_conf_sub_location_info_t));
        loc = njt_array_push(ret->location_array);
        njt_memset(loc, 0, sizeof(njt_conf_sub_location_info_t));
        loc->location.data = njt_palloc(pool, 4);
        njt_str_set(&loc->location, "/add");
        loc->location_rule.data = njt_palloc(pool, 1);
        njt_str_set(&loc->location_rule, "");
        loc->location_body.data = njt_palloc(pool, 100);
        njt_str_set(&loc->location_body, "{ set $A; set $B; return 200 OK;}");
        loc->proxy_pass.data = njt_palloc(pool, 20);
        njt_str_set(&loc->proxy_pass, "/server_upstream");
        // loc->sub_location_array = njt_array_create(pool, 1, sizeof(njt_conf_sub_location_info_t));
        // sub_loc = njt_array_push(loc->sub_location_array);
        // njt_memset(sub_loc, 0, sizeof(njt_conf_sub_location_info_t));
        // sub_loc->location.data = njt_palloc(pool, 4);
        // njt_str_set(&sub_loc->location, "/add");
        // sub_loc->location_rule.data = njt_palloc(pool, 1);
        // njt_str_set(&sub_loc->location_rule, "");
        // sub_loc->location_body.data = njt_palloc(pool, 100);
        // njt_str_set(&sub_loc->location_body, "{ set $A; set $B; return 200 OK;}");
        // sub_loc->proxy_pass.data = njt_palloc(pool, 20);
        // njt_str_set(&sub_loc->proxy_pass, "/server_upstream");
    } else {
        ret->type.data = njt_palloc(pool, 3);
        njt_str_set(&ret->type, "del");
        ret->location.data = njt_palloc(pool, 4);
        njt_str_set(&ret->location, "/add");
        ret->location_rule.data = njt_palloc(pool, 1);
        njt_str_set(&ret->location_rule, "");
    }
    return ret;
}

njt_conf_element_t* get_test_element_ptr(njt_pool_t *pool, njt_uint_t add) {
    njt_conf_element_t    *ret, *loc;
    njt_array_t           *cf;
    njt_str_t             s_loc, s_loc_name, s_set, s_a, s_200, s_ret, *cur;

    s_set.data = njt_palloc(pool, 3);
    njt_str_set(&s_set, "set");
    s_a.data = njt_palloc(pool, 2);
    njt_str_set(&s_a, "$A");
    s_ret.data = njt_palloc(pool, 6);
    njt_str_set(&s_ret, "return");
    s_200.data = njt_palloc(pool, 6);
    njt_str_set(&s_200, "200 OK");
    s_loc_name.data = njt_palloc(pool, 4);
    njt_str_set(&s_loc_name, "/add");
    s_loc.data = njt_palloc(pool, 8);
    njt_str_set(&s_loc, "location");


    ret = njt_pcalloc(pool, sizeof(njt_conf_element_t));

    cf = njt_array_create(pool, 1, sizeof(njt_str_t));
    cur = njt_array_push(cf);
    njt_memcpy(cur, &s_loc_name, sizeof(njt_str_t));
    loc = njt_conf_create_block(pool, cf);
    // add locations
    
    cf = njt_array_create(pool, 2, sizeof(njt_str_t));

    cur = njt_array_push(cf);
    njt_memcpy(cur, &s_set, sizeof(njt_str_t));
    cur = njt_array_push(cf);
    njt_memcpy(cur, &s_a, sizeof(njt_str_t));
    njt_conf_add_cmd(pool, loc, cf);

    cf = njt_array_create(pool, 2, sizeof(njt_str_t));
    cur = njt_array_push(cf);
    njt_memcpy(cur, &s_ret, sizeof(njt_str_t));
    cur = njt_array_push(cf);
    njt_memcpy(cur, &s_200, sizeof(njt_str_t));
    njt_conf_add_cmd(pool, loc, cf);


    njt_conf_add_block(pool, ret, loc, &s_loc);

    return ret;
}

njt_int_t
njt_conf_dyn_loc_save_pub_to_file(njt_pool_t *pool, njt_log_t *log, 
    njt_conf_element_t *root)
{
    size_t      length;
    njt_int_t   rc;
    njt_uint_t  create;
    njt_file_t  file;
    njt_str_t   out;
    njt_str_t   file_name = njt_string("dynloc.json");



    njt_memzero(&file, sizeof(njt_file_t));

    file.name = file_name;
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
        njt_conf_dyn_loc_get_pub_json_length(root, &length, 1);
        out.data = njt_palloc(pool, length + 1);
        if (out.data == NULL) {
            return NJT_ERROR;
        }
        out.len = 0;
        njt_conf_dyn_loc_get_pub_json_str(root, &out, 1);
    }

    if (njt_write_file(&file, out.data, out.len, 0) == NJT_ERROR) {
        rc = NJT_ERROR;
    }

    njt_pfree(pool, out.data);
    njt_close_file(file.fd);
    njt_pfree(pool, file.name.data);
    

    return rc;
}
#endif

