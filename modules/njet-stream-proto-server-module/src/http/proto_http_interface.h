#ifndef NJT_PROTO_HTTP_INTERFACE_H_
#define NJT_PROTO_HTTP_INTERFACE_H_
#include "../njt_tcc.h"
#define TCC_PROTO_CTX_HTTP  1
typedef int (*proto_http_on_header)(const char *k, size_t k_len,const char *v, size_t v_len,void* cb_data);
//todo: body process not implemented yet
typedef int (*proto_http_on_body)(const char *k, size_t k_len,void* cb_data);
//todo: should add more params
typedef int (*proto_http_req)(void* cb_data);

extern int  proto_http_init(tcc_stream_request_t *r,proto_http_on_header on_header,proto_http_on_body on_body, proto_http_req on_req);
extern int  proto_http_parse(tcc_stream_request_t *r,tcc_str_t *msg);
#endif