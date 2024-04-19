
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef NJET_MAIN_NJT_HTTP_CLIENT_UTIL_H
#define NJET_MAIN_NJT_HTTP_CLIENT_UTIL_H

#include <njt_core.h>
#include <njt_http.h>


typedef enum{
    NJT_HTTP_CLIENT_UTIL_METHOD_GET = 0,
    NJT_HTTP_CLIENT_UTIL_METHOD_PUT,
    NJT_HTTP_CLIENT_UTIL_METHOD_POST
} NJT_HTTP_CLIENT_UTIL_METHOD;


#if (NJT_OPENSSL)
typedef struct njt_http_client_ssl_conf_s {
    njt_uint_t    ssl_protocols;
    njt_str_t     ssl_ciphers;
    njt_ssl_t     *ssl;
    njt_flag_t    ssl_enable;
} njt_http_client_ssl_conf_t;
#endif


typedef struct njt_http_client_metadata_conf_s {
    njt_array_t                     additinal_send_header;    //用户自定义额外header
    njt_array_t                     query_params;   //get method query param
    njt_str_t                       host;
    njt_str_t                       uri;
    njt_buf_t                       *send_buf;
    njt_buf_t                       *recv_buf;
    njt_chain_t                     *recv_chain;
    njt_chain_t                     *last_chain_node;
    void                            *parser;
#if (NJT_HTTP_SSL)
    njt_str_t                       ssl_name;
#endif
    //response data
    ssize_t                         resource_size; //应该返回数据大小
    ssize_t                         current_size;  //当前已返回数据大小
} njt_http_client_metadata_conf_t;


typedef struct njt_http_client_header_param_s {
    njt_str_t     key;
    njt_str_t     value;
} njt_http_client_header_param_t;


typedef struct njt_http_client_util_s {
    NJT_HTTP_CLIENT_UTIL_METHOD     method;
    njt_str_t                       url;
    njt_peer_connection_t           *peer;
    void                            *data;  //customer data
    njt_str_t                       post_data;
    njt_pool_t                      *pool;
    
    njt_http_client_metadata_conf_t  metadata;

#if (NJT_HTTP_SSL)
    njt_str_t                       ssl_name;
#endif

#if (NJT_OPENSSL)
    njt_http_client_ssl_conf_t ssl;
#endif

    //http client util start success handler, data is custom data
    void (*start_success_handler)(void *data);
    
    //read timeout handler, data is custom data
    void (*read_timeout_handler)(void *data);
    //write timeout handler
    void (*write_timeout_handler)(void *data);


    //ssl handshake 成功handler
    void (*ssl_handshake_success_handler)(void *data);
    //ssl handshake 失败handler
    void (*ssl_handshake_fail_handler)(void *data);

    //每一次read事件调用处理，rc为每次调用read事件的返回值，可供使用者状态更新
    //NJT_ERROR： read调用出错，错误结束
    //NJT_DONE： http请求处理完成，正常结束
    //NJT_ABORT： http请求异常结束，异常终止
    //其他，继续read事件循环
    void (*read_event_result_handler)(void *data, njt_int_t rc);

    //每一次write事件调用处理，rc为每次调用write事件的返回值，可供使用者状态更新
    //NJT_ERROR： read调用出错，错误结束
    //NJT_DONE： http请求处理完成，正常结束
    //NJT_OK: http请求处理完成，正常结束
    //其他，继续write事件循环
    void (*write_event_result_handler)(void *data, njt_int_t rc);

    //parse line，可根据rc值来判断parse结果
    //rc: NJT_OK or NJT_ERROR
    void (*parse_line_handler)(void *data, njt_int_t rc);
    
    //parse header，可根据rc值来判断parse结果（最终结果）
    void (*parse_header_handler)(void *data, njt_int_t rc);
    //parse header， 每一个header都会调用，可以通过h->key, h->value 获取数据
    void (*parse_header_data_handler)(void *data, njt_table_elt_t *h);
   
    //parse body，可根据rc值来判断parse结果（最终结果）
    void (*parse_body_handler)(void *data, njt_int_t rc);
    //parse body content， 每次受到的中间数据， 数据放在[start, end)指针范围内，start为数据开始，end为数据最后一个字符的下一位
    void (*parse_body_data_handler)(void *data, u_char *start, u_char *end);
}njt_http_client_util_t;


typedef struct njt_http_client_util_parse_s {
    njt_uint_t          state;
    njt_uint_t          code;
    njt_flag_t          done;
    njt_flag_t          body_used;
    njt_uint_t          stage;
    u_char              *status_text;
    u_char              *status_text_end;
    njt_uint_t          count;
    njt_flag_t          chunked;
    off_t               content_length_n;
    njt_array_t         headers;
    u_char              *header_name_start;
    u_char              *header_name_end;
    u_char              *header_start;
    u_char              *header_end;
    u_char              *body_start;

    njt_int_t           (*process)(njt_http_client_util_t *client_util);

    njt_msec_t          start;
}njt_http_client_util_parse_t;


/*
 *  create client util
 *  (IN) method: set http request method, now support get\put\post
 *  (IN) url: need set url, eg: http://www.baidu.com/a/b/c or https://www.baidu.com/a/b/c
 * （IN） post_data: if method is put or post need set post_data
 *  (IN) custom_data: custom data, self function can get the data； use client_util->data
 *  (OUT) if has error, return NULL; if success, return client_util object
*/
njt_http_client_util_t *njt_http_client_util_create(NJT_HTTP_CLIENT_UTIL_METHOD method,
    njt_str_t url, njt_str_t post_data, void *custom_data);

//add custom header
njt_int_t njt_http_client_util_add_header(njt_http_client_util_t *client_util, njt_str_t key, njt_str_t value);

//if method is get, you can add query_param
njt_int_t njt_http_client_util_add_query_param(njt_http_client_util_t *client_util, njt_str_t key, njt_str_t value);

// start http client request, if has error, will free client_util pool memory
njt_int_t njt_http_client_util_start(njt_http_client_util_t *client_util);

#endif //NJET_MAIN_NJT_HTTP_CLIENT_UTIL_H
