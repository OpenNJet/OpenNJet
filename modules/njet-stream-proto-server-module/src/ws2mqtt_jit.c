#include <arpa/inet.h>
#include <http/proto_http_interface.h>
#include <ws/proto_ws_interface.h>

#include <string.h>
#include <stdlib.h>


  
typedef struct TccWSHeaders_ {
  char *agent;
  char *path;
  char *method;
  char *protocol;
  char *host;
  char *origin;
  char *upgrade;
  char *referer;
  char *connection;
  char *ws_protocol;
  char *ws_key;
  char *ws_sock_ver;

  char *ws_accept;
  char *ws_resp;
} TccWSHeaders;
typedef struct WSctx_ {

  unsigned       handshake:1;

  TccWSHeaders headers;           /* HTTP headers */
  //WSFrame *frame;               /* frame headers */
  void *message;           /* message */
  //WSStatus status;              /* connection status */

  tcc_stream_request_t *r;

} WSctx;
//tips: k,v are c strings in fact
int on_http_header(const char *key, size_t k_len,const char *value, size_t v_len,void *cb_data){
    tcc_stream_request_t* r=cb_data;
    //proto_server_log(NJT_LOG_INFO,"on header: %d:%d",k_len,v_len);
    WSctx* ctx=tcc_get_client_app_ctx(r);
    TccWSHeaders *headers=&ctx->headers;
    char* data=proto_malloc(r,v_len+1);
    memcpy(data,value,v_len+1);
  proto_server_log(NJT_LOG_INFO,"%s:%s",key,value);
  if (strcasecmp("Host", key) == 0) {
    headers->host = data;
  }
  else if (strcasecmp("Origin", key) == 0)
    headers->origin = data;
  else if (strcasecmp("Upgrade", key) == 0)
    headers->upgrade = data;
  else if (strcasecmp("Connection", key) == 0)
    headers->connection = data;
  else if (strcasecmp("Sec-WebSocket-Protocol", key) == 0)
    headers->ws_protocol = data;
  else if (strcasecmp("Sec-WebSocket-Key", key) == 0)
    headers->ws_key = data;
  else if (strcasecmp("Sec-WebSocket-Version", key) == 0)
    headers->ws_sock_ver = data;
  else if (strcasecmp("User-Agent", key) == 0)
    headers->agent = data;
  else if (strcasecmp("Referer", key) == 0)
    headers->referer = data;
    return NJT_OK;
};
int run_proto_msg(tcc_stream_request_t *r){
   int type;
   size_t length;
   int len=0;
   char *buf;
   int rtype;


   ws_iter_start(r,&length,&type);
   rtype = type;
   if(type == WS_OP_PING) {
      rtype = WS_OP_PONG;
   } else if (type == WS_OP_PONG) {
       return APP_OK;
   }

   proto_server_log(NJT_LOG_DEBUG,"ws run_proto_msg:type%d,len:%d",type,length);

   len=ws_iter_next(r,&buf);
   while (len>0) {
    proto_server_log(NJT_LOG_DEBUG,"send to up:len:%d",len);
    proto_server_send_upstream(r,buf,len);
    len=ws_iter_next(r,&buf);
   }

   return APP_OK;

}
int destroy_proto_msg(tcc_stream_request_t *r)
{
    proto_server_log(NJT_LOG_DEBUG,"tcc destroy_proto_msg");
    ws_destory_ctx(r);
}
int proto_server_process_message(tcc_stream_request_t *r, tcc_str_t *msg){
    njt_int_t rc = 0;
    proto_server_log(NJT_LOG_DEBUG,"tcc proto_server_process_message, len:%d",msg->len);
    WSctx* ctx=tcc_get_client_app_ctx(r);
    if (ctx && !ctx->handshake) {
        rc = proto_http_parse(r,msg);
        proto_server_log(NJT_LOG_DEBUG,"2 tcc create_proto_msg handshake end rc=%d",rc);
        return APP_AGAIN;
    }
    rc = ws_parse(r,msg);
    proto_server_log(NJT_LOG_DEBUG,"tcc create_proto_msg end rc=%d",rc);
    if (rc==APP_OK) {
        run_proto_msg(r);
        destroy_proto_msg(r);
    }
    return rc;
    //todo: return ws msg process
}
int proto_server_upstream_message(tcc_stream_request_t *r, tcc_str_t *msg){

  proto_server_log(NJT_LOG_DEBUG,"proto_server_upstream_message len=%d",msg->len);
  r->used_len=msg->len;
  if (msg->len>0) ws_send(r,WS_OP_BINARY,msg->len,msg->data,1);
}
static int ws_send_handshake_headers(tcc_stream_request_t *r)
{
  u_char *digest, *dig64;
  size_t  l64;
  WSctx *ctx = tcc_get_client_app_ctx(r);
  TccWSHeaders *headers=&ctx->headers;
  size_t klen = strlen(headers->ws_key);
  size_t mlen = strlen(WS_MAGIC_STR);
  size_t len = klen + mlen;
  char *s = proto_malloc(r, klen + mlen + 1);


  memcpy(s, headers->ws_key, klen);
  memcpy(s + klen, WS_MAGIC_STR, mlen+1);

  digest= proto_util_sha1(r, s, len, 20);
  int i=0;

  proto_util_base64(r,digest,20,&dig64, &l64);

  //todo:  verify headers
  proto_server_send(r,WS_SWITCH_PROTO_STR,34,0);
  proto_server_send(r,"Server: NJet\r\n",14,0);
  proto_server_send(r,"Connection: Upgrade\r\n",21,0);
  proto_server_send(r,"Upgrade: websocket\r\n",20,0);
  proto_server_send(r,"Sec-WebSocket-Accept: ",22,0);
  proto_server_send(r,dig64,l64,0);
  proto_server_send(r,"\r\n",2,0);
  //proto_server_send(r,"Sec-WebSocket-Extensions: permessage-deflate\r\n",44);
  proto_server_send(r,"Sec-WebSocket-Protocol: mqtt\r\n",30,0);


  proto_server_send(r,"\r\n",2,1);

  return NJT_OK;
}
int on_http_request(void* cb_data){
    tcc_stream_request_t *r=cb_data;
    WSctx* ctx=tcc_get_client_app_ctx(r);
    proto_server_log(NJT_LOG_INFO,"ws on http req");
    ws_send_handshake_headers(r);
    ctx->handshake=1;
    return NJT_OK;
}

int create_proto_msg(tcc_stream_request_t *r, tcc_str_t *msg){
    njt_int_t rc = 0;
    proto_server_log(NJT_LOG_DEBUG,"tcc create_proto_msg, len:%d",msg->len);
    WSctx* ctx=tcc_get_client_app_ctx(r);
    if (ctx && !ctx->handshake) {
        rc = proto_http_parse(r,msg);
        proto_server_log(NJT_LOG_DEBUG,"2 tcc create_proto_msg handshake end rc=%d",rc);
        return rc;
    }
    rc = ws_parse(r,msg);
    proto_server_log(NJT_LOG_DEBUG,"tcc create_proto_msg end rc=%d",rc);
    return rc;
    //todo: return ws msg process
}
int proto_server_process_connection(tcc_stream_request_t *r){
    WSctx *cli_ctx = proto_malloc(r, sizeof(WSctx));
    memset(cli_ctx, 0, sizeof(WSctx));
    cli_ctx->r = r;
    tcc_set_client_app_ctx(r,cli_ctx);
    proto_http_init(r,on_http_header,NULL,on_http_request);
    ws_init_conn(r,NULL); //run_proto_msg
    return NJT_OK;
}
int proto_server_process_connection_close(tcc_stream_request_t *r)
{
  return NJT_OK;
}

int has_proto_msg(tcc_stream_request_t *r)
{   int rc;
    rc = ws_iter_has_data(r);
    proto_server_log(NJT_LOG_DEBUG,"has_proto_msg,rc=%d",rc);

    return rc;
}
