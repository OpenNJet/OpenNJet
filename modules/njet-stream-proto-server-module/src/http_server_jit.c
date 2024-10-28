#include <http/proto_http_interface.h>
#include <ws/proto_ws_interface.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>





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



static int ws_send_handshake_headers(tcc_stream_request_t *r);
//tips: k,v are c strings in fact
int on_http_header(const char *key, size_t k_len,const char *value, size_t v_len,void *cb_data){
    tcc_stream_request_t* r=cb_data;
    //proto_server_log(NJT_LOG_INFO,"on header: %d:%d",k_len,v_len);
    WSctx* ctx=tcc_get_client_app_ctx(r);
    TccWSHeaders *headers=&ctx->headers;
    char* data=proto_malloc(r,v_len+1);
    memcpy(data,value,v_len+1);
  proto_server_log(NJT_LOG_DEBUG,"%s:%s",key,value);
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

  struct sockaddr_in addr;
  int s;
  char buf[1024];
  tcc_str_t  msg;
  tcc_str_t  port = njt_string("7791");
  tcc_str_t  port2 = njt_string("7792");
  tcc_str_t  ip = njt_string("127.0.0.1\0");
  tcc_str_t remote_ip = njt_string("127.0.0.1");

  tcc_str_t fmt_data = njt_string("HTTP/1.1 200 OK\r\n"
  "Server: njet/3.0.1\r\n"
  "Date: Mon, 02 Sep 2024 06:59:00 GMT\r\n"
  "Content-Type: application/octet-stream\r\n"
  "Content-Length: %d\r\n"
  "Connection: keep-alive\r\n"
  "\r\n"
  "%V"
 );
  
  addr.sin_family = AF_INET;
  if(njt_memcmp(r->addr_text->data,remote_ip.data,remote_ip.len) == 0) {
    addr.sin_port = htons(njt_atoi(port.data,port.len));
    proto_server_log(NJT_LOG_DEBUG,"1 get  dest port=%V!",&port);
  } else {
    proto_server_log(NJT_LOG_DEBUG,"2 get  dest port=%V!",&port2);
    addr.sin_port = htons(njt_atoi(port2.data,port2.len));
  }
    WSctx* ctx=tcc_get_client_app_ctx(r);
    if(ctx->handshake ==1) {
      //tcc_sleep(1);
      //proto_server_send(r,fmt_data.data,fmt_data.len);
      if (!inet_aton(ip.data, &addr.sin_addr)) {
			   return APP_ERROR;
      }
      s = socket(AF_INET, SOCK_STREAM, 0);
      if (tcc_connect(s, (const struct sockaddr *)&addr, sizeof(addr)) == -1) {

          proto_server_log(NJT_LOG_DEBUG,"connect error!");
          
          close(s);
          return APP_ERROR;
        } else {
          proto_server_log(NJT_LOG_DEBUG,"connect succ!");
        }
        int ret;
        while(1) {
          memset(buf,0,sizeof(buf));
          ret = tcc_recv(s,buf,sizeof(buf),0);
          if(ret > 0) {
            int send_len = fmt_data.len + ret + 100;
            msg.data = buf;
            msg.len = ret;
            char* data=proto_malloc(r,send_len);
            char *last = njt_snprintf(data,send_len,fmt_data.data,ret,&msg);
            proto_server_send(r,data,last - data);
            break;
          } else if(ret == 0) {
            break;
          }
        }
      ctx->handshake = 2;
       cli_close(r);
    }
   return APP_OK;

}

int proto_server_process_preread(tcc_stream_request_t *r, tcc_str_t *msg){
    return NJT_DECLINED;
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
  proto_server_send(r,WS_SWITCH_PROTO_STR,34);
  proto_server_send(r,"Server: NJet\r\n",14);
  proto_server_send(r,"Connection: Upgrade\r\n",21);
  proto_server_send(r,"Upgrade: websocket\r\n",20);
  proto_server_send(r,"Sec-WebSocket-Accept: ",22);
  proto_server_send(r,dig64,l64);
  proto_server_send(r,"\r\n",2);
  proto_server_send(r,"\r\n",2);

  return NJT_OK;
}


    
int on_http_request(void* cb_data){
    tcc_stream_request_t *r=cb_data;
    WSctx* ctx=tcc_get_client_app_ctx(r);
    proto_server_log(NJT_LOG_DEBUG,"ws on http req");
    //ws_send_handshake_headers(r);
    //cli_set_session(r,r->session.data,r->session);
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
    rc = APP_OK;
    r->used_len = msg->len;
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
int destroy_proto_msg(tcc_stream_request_t *r)
{
    proto_server_log(NJT_LOG_DEBUG,"tcc destroy_proto_msg");
    return NJT_OK;
}
int has_proto_msg(tcc_stream_request_t *r)
{  

    int rc = APP_FALSE;
    WSctx* ctx=tcc_get_client_app_ctx(r);
    if(ctx->handshake ==1) {
      rc = APP_TRUE;
    }
    proto_server_log(NJT_LOG_DEBUG,"has_proto_msg,rc=%d",rc);
    return rc;
}