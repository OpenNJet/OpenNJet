/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <sys/socket.h>
#include "njt_stream_sniffer.h"
#include "libtcc.h"

//#define NJT_SNIFFER_BUFFER_SIZE  4096
#define NJT_SNIFFER_TCC_PATH  "/usr/local/njet/lib/tcc"

static njt_stream_session_t * stream_session = NULL;





typedef struct {
    njt_flag_t      sniffer_enabled;
    TCCState *s;
}njt_stream_sniffer_srv_conf_t;

static njt_int_t njt_stream_sniffer_init(njt_conf_t *cf);
static void *njt_stream_sniffer_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_sniffer_merge_srv_conf(njt_conf_t *cf, void *parent, void *child);
static char *
njt_stream_read_sniffer_filter_file(njt_conf_t *cf, njt_command_t *cmd, void *conf);

/**
 * This module provide callback to istio for http traffic
 *
 */
static njt_command_t njt_stream_sniffer_commands[] = {
    { njt_string("sniffer"),
      NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_sniffer_srv_conf_t, sniffer_enabled),
      NULL },
    {
      njt_string("sniffer_filter_file"),
      NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
      njt_stream_read_sniffer_filter_file,     // do custom config
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL
    },
    njt_null_command /* command termination */
};




/* The module context. */
static njt_stream_module_t njt_stream_sniffer_module_ctx = {
    NULL, /* preconfiguration */
    njt_stream_sniffer_init, /* postconfiguration */
    NULL,
    NULL, /* init main configuration */
    njt_stream_sniffer_create_srv_conf, /* create server configuration */
    njt_stream_sniffer_merge_srv_conf /* merge server configuration */

};

/* Module definition. */
njt_module_t njt_stream_sniffer_module = {
    NJT_MODULE_V1,
    &njt_stream_sniffer_module_ctx, /* module context */
    njt_stream_sniffer_commands, /* module directives */
    NJT_STREAM_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NJT_MODULE_V1_PADDING
};

static TCCState *njt_stream_sniffer_create_tcc(){
    TCCState *tcc = tcc_new();
    if(tcc == NULL) {
        return NULL;
    }
    tcc_set_output_type(tcc, TCC_OUTPUT_MEMORY);
    tcc_set_options(tcc,"-Werror");
    tcc_set_lib_path(tcc,NJT_SNIFFER_TCC_PATH); 
    tcc_add_include_path(tcc,NJT_SNIFFER_TCC_PATH); 
	return tcc;
}
static void *njt_stream_sniffer_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_sniffer_srv_conf_t  *conf;

    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "nginmeshdest create serv config");

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_sniffer_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->sniffer_enabled = NJT_CONF_UNSET;
    conf->s = NJT_CONF_UNSET_PTR;
    return conf;
}


static char *njt_stream_sniffer_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
     njt_stream_sniffer_srv_conf_t *prev = parent;
     njt_stream_sniffer_srv_conf_t *conf = child;
     njt_conf_merge_value(conf->sniffer_enabled, prev->sniffer_enabled, 0);
    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "nginmeshdest merge serv config");
    return NJT_CONF_OK;
}



 njt_int_t njt_stream_sniffer_tcc_check_data(njt_stream_session_t *s){
    njt_connection_t                   *c;
    njt_int_t    rc;
    int          data_len; 
    njt_stream_sniffer_srv_conf_t  *sscf;
   
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_sniffer_module);

    c = s->connection;
    data_len = c->buffer->last -  c->buffer->pos;

    stream_session = s;
    int (* check_pack )(u_char *,int)=tcc_get_symbol(sscf->s,"check_pack");
    rc=check_pack(c->buffer->pos,data_len);
    stream_session = NULL;
    return rc;
     
 }


 njt_int_t njt_stream_sniffer_handler(njt_stream_session_t *s)
{
    // u_char                             *last, *p;
    //size_t                              len;
    njt_int_t                           rc;
    njt_connection_t                   *c;
    njt_stream_sniffer_srv_conf_t  *sscf;
    //njt_uint_t   i;
    //njt_stream_sniffer_data_t            *sniffer_data;

    c = s->connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0, "njt_stream_sniffer_handler");

    sscf = njt_stream_get_module_srv_conf(s, njt_stream_sniffer_module);

    if (!sscf->sniffer_enabled) {
        return NJT_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        return NJT_DECLINED;
    }

    if (c->buffer == NULL) {
        return NJT_AGAIN;
    }

    rc = njt_stream_sniffer_tcc_check_data(s);
    if(rc == NJT_AGAIN) {
        return rc;
    }
    if(rc == NJT_ERROR) {
#ifdef TCP_REPAIR

                njt_int_t aux = 1;
                if ( setsockopt( c->fd, SOL_TCP, TCP_REPAIR, 
                                    &aux, sizeof( aux )) < 0 )
                {
                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_stream_sniffer_handler");
                }
#endif
        return NJT_ERROR;
    }
    

	return NJT_DECLINED;
}


// add handler to pre-access
// otherwise, handler can't be add as part of config handler if proxy handler is involved.

static njt_int_t njt_stream_sniffer_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;


    njt_log_debug(NJT_LOG_DEBUG_EVENT,  njt_cycle->log, 0, "ngin mesh init invoked");


    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_sniffer_handler;

    return NJT_OK;
}
int sniffer_get_data(int pos,char* buffer,int buffer_len) {
    njt_int_t  len;
    njt_connection_t                   *c;
    if(stream_session == NULL) {
        return 0;
    }
    c = stream_session->connection;
    len = buffer_len;
    if (len >  c->buffer->last - c->buffer->pos - pos) {
            len = c->buffer->last - c->buffer->pos - pos;
    }
    if (len < 0) {
        return 0;
    }
    njt_memcpy(buffer,c->buffer->pos,len);
    return len;
}
/*
    dump 的长度，是16 进制字符数。 区别与 njt_hex_dump dump 的字节数。
*/
static u_char *
njt_sniffer_hex_dump(u_char *dst, u_char *src, size_t len)
{
    static u_char  hex[] = "0123456789abcdef";
    if (len == 0) {
        return dst;
    }
    for (;;) {
        *dst++ = hex[*src >> 4];
        len --;
        if(len == 0) {
            return dst;
        }
        *dst++ = hex[*src++ & 0xf];
        len --;
        if(len == 0) {
            return dst;
        }
    }

    return dst;
}

int sniffer_get_hex_data(int pos,char* buffer,int buffer_len) {
    njt_int_t  len;
    njt_connection_t                   *c;
    if(stream_session == NULL) {
        return 0;
    }
    c = stream_session->connection;
    len = (buffer_len/2) + (buffer_len%2);
    if (len >  c->buffer->last - c->buffer->pos - pos) {
            len = c->buffer->last - c->buffer->pos - pos;
    }
    if (len < 0) {
        return 0;
    }
    len  = len * 2;
    if (len > buffer_len) {
        len = buffer_len;
    }

     njt_sniffer_hex_dump((u_char *)buffer,(u_char *)c->buffer->pos+pos,len);
    return len;
}
int sniffer_get_hex_cmp(int pos, char* dst) {
	 njt_pool_t *pool = NULL;
     njt_int_t  rel_len,rc;
     njt_str_t data,low_dst;
     u_char* src;
     njt_int_t  len;
     njt_connection_t                   *c;
     u_char *max_pos;
    if(stream_session == NULL) {
        return NJT_ERROR;
    }
     c = stream_session->connection;  //c->buffer->last - c->buffer->pos
     src = c->buffer->pos;
     len = njt_strlen(dst);
     max_pos = (u_char *)src + pos + (len/2) + (len%2);

    
   
    if ( max_pos >= c->buffer->last ) {
        return  NJT_AGAIN;
    }
    
     rel_len = len;
     if(len % 2 == 1) {
        rel_len = len + 1;
     }
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);

    if(pool == NULL){
	    return  NJT_ERROR;
    }
    rc = NJT_DECLINED;
    data.len = rel_len;
    data.data = njt_pcalloc(pool,data.len);
    low_dst.len = len;
    low_dst.data = njt_pcalloc(pool,low_dst.len);
    if(data.data == NULL ||  low_dst.data == NULL) {
         njt_destroy_pool(pool);
         rc = NJT_ERROR;
         goto end;
    }

    njt_strlow(low_dst.data,(u_char *)dst,len);

    njt_hex_dump(data.data,(u_char *)src+pos,rel_len/2);

    if(njt_memcmp(data.data,low_dst.data,len) == 0) {
         rc =  NJT_OK;
    }
end:
    return  rc;
} 

 int sniffer_hex_cmp(char* src,int pos, char* dst) {
	 njt_pool_t *pool = NULL;
     njt_int_t  rel_len,rc;
     njt_str_t data,low_dst;
     njt_int_t  len;
     njt_connection_t                   *c;
     u_char *max_pos;

     len = njt_strlen(dst);
     max_pos = (u_char *)src + pos + (len/2) + (len%2);

    if(stream_session != NULL) {
        c = stream_session->connection;  //c->buffer->last - c->buffer->pos
        if ((u_char *)src < c->buffer->pos || max_pos >= c->buffer->last ) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "sniffer_hex_cmp upper bound of c->buffer!");
            return  NJT_ERROR;
        }
    }
     rel_len = len;
     if(len % 2 == 1) {
        rel_len = len + 1;
     }
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);

    if(pool == NULL){
	    return  NJT_ERROR;
    }
    rc = NJT_DECLINED;
    data.len = rel_len;
    data.data = njt_pcalloc(pool,data.len);
    low_dst.len = len;
    low_dst.data = njt_pcalloc(pool,low_dst.len);
    if(data.data == NULL ||  low_dst.data == NULL) {
         njt_destroy_pool(pool);
         rc = NJT_ERROR;
         goto end;
    }

    njt_strlow(low_dst.data,(u_char *)dst,len);

    njt_hex_dump(data.data,(u_char *)src+pos,rel_len/2);

    if(njt_memcmp(data.data,low_dst.data,len) == 0) {
         rc =  NJT_OK;
    }
end:
    return  rc;
} 


static char *
njt_stream_read_sniffer_filter_file(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    u_char              *data_info;
    njt_fd_t            fd;
    njt_file_info_t     fi;
    size_t              size,pos;
    ssize_t             n;
    njt_str_t           full_name,sniffer_data,all_code,code_body;
    njt_str_t  *value;
    njt_int_t  rc;
    njt_str_t  header_code = njt_string("#include <tcclib.h>; extern int sniffer_get_hex_cmp(int pos, char* dst);extern int sniffer_get_hex_data(int pos,char* buffer,int buffer_len) ;extern int sniffer_get_data(int pos,char* buffer,int buffer_len);extern  int sniffer_hex_cmp(char* src,int src_len,char* dst); int check_pack(char *bytes,int len)");
    //njt_str_t  header_code = njt_string("#include <tcclib.h>;extern int sniffer_get_hex_data(int pos,char* buffer,int buffer_len) ;extern int sniffer_get_data(int pos,char* buffer,int buffer_len);extern  int sniffer_hex_cmp(char* src,int src_len,char* dst); int check_pack(char *bytes,int len)");

    njt_stream_sniffer_srv_conf_t *sscf = conf;

    
    if(sscf->s != NJT_CONF_UNSET_PTR && sscf->s != NULL) {
         return "is duplicate";
    }
    value = cf->args->elts;
    full_name = value[1];
    if(njt_conf_full_name((void *)cf->cycle, &full_name, 1) != NJT_OK) {
       return NJT_CONF_ERROR;
    }

    //get register info
    fd = njt_open_file(full_name.data, NJT_FILE_RDONLY, NJT_FILE_OPEN, 0);
    if(fd == NJT_INVALID_FILE) {
        return NJT_CONF_ERROR;
    }

    if(njt_fd_info(fd, &fi) == NJT_FILE_ERROR) {
         return NJT_CONF_ERROR;
    }

    size = njt_file_size(&fi);
  

    if(size < 1){
        return NJT_CONF_ERROR;
    }

    data_info = (u_char *)njt_pcalloc(cf->pool, size);

    all_code.len  = size + header_code.len + 20;
    all_code.data = (u_char *)njt_pcalloc(cf->pool,all_code.len);
    if(data_info == NULL || all_code.data == NULL){
        return NJT_CONF_ERROR;
    }
   
    for(pos = 0;pos < size;) {
        //need_len = size - pos;
        n = njt_read_fd(fd, data_info+pos, size - pos);

        if (n < 0) {
            return NJT_CONF_ERROR;
        }
        pos += n;
    }

    sniffer_data.data = data_info;
    sniffer_data.len = size;

    if (njt_close_file(fd) == NJT_FILE_ERROR) {

        //return NJT_CONF_OK;
    }
    data_info = njt_snprintf(all_code.data,all_code.len,"%V {%V}\n",&header_code,&sniffer_data);
    //data_info = njt_snprintf(export_code.data,export_code.len,"#include <tcclib.h>;int check_pack(char *bytes,int len) {%V}\n",&sniffer_data);
    code_body.data = all_code.data;
    code_body.len =  data_info - all_code.data;


    sscf->s = njt_stream_sniffer_create_tcc();
    if (sscf->s == NULL) {
        return NJT_CONF_ERROR;
    }

 
    rc = tcc_compile_string(sscf->s,(const char *)code_body.data);
    if(rc == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }
    //tcc_add_symbol(sscf->s,"sniffer_hex_cmp",sniffer_hex_cmp);
    //tcc_add_symbol(sscf->s,"sniffer_get_hex_cmp",sniffer_get_hex_cmp);
	tcc_relocate(sscf->s, TCC_RELOCATE_AUTO);


    int (* pack_insp )(u_char *,int)=tcc_get_symbol(sscf->s,"check_pack");
    int ret=pack_insp(code_body.data,(int)code_body.len);

    printf("%d",ret);
    

    return NJT_CONF_OK;
}
