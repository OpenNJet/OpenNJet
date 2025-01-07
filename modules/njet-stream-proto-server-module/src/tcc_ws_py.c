#include <tcclib.h>
#include <njt_tcc.h>
#include <tcc_ws.h>
#include <ctype.h>

typedef struct app_server_s {
  /* Server Status */
  int gen_client_id;
  int server_id;
} app_server_t;

typedef struct app_client_s {
  /* Server Status */
  tcc_str_t *init_data;
  int  id;
} app_client_t;

int ws_app_on_connection(tcc_stream_request_t *r,WSMessage *msg) {
    app_server_t *app_server;
    app_client_t *app_client = proto_malloc(r,sizeof(app_client_t));
    if(app_client != NULL) {
        app_client->init_data = r->addr_text;
        app_server = tcc_client_get_app_srv_ctx(r);
        app_client->id = ++app_server->gen_client_id;
        tcc_set_client_app_ctx(r,app_client);
    }
    ws_send_handshake_headers(r, msg->headers);
    if(msg->headers != NULL) {
        proto_server_log(NJT_LOG_DEBUG, "tcc from ws_app_on_connection path: %s!",msg->headers->path);
    }
    return NJT_OK;
}

int ws_app_on_message(tcc_stream_request_t *r,WSMessage *msg) {
    tcc_str_t data,out_data;
    int len;
    app_client_t *app_client = tcc_get_client_app_ctx(r);
    if(app_client == NULL) {
         proto_server_log(NJT_LOG_DEBUG, "tcc app_client null!");
         return NJT_ERROR;
    }
    app_server_t *app_server = tcc_client_get_app_srv_ctx(r);
    if(app_server == NULL) {
         proto_server_log(NJT_LOG_DEBUG, "tcc app_server  null!");
         return NJT_ERROR;
    }

    if(msg->opcode == WS_OPCODE_PING) {
        proto_server_log(NJT_LOG_DEBUG, "1 tcc from ws_app_on_message ping!");
        return NJT_OK;
    }
    proto_server_log(NJT_LOG_DEBUG, "1 tcc from ws_app_on_message msg->opcode=%d!",msg->opcode);

    data.data = msg->payload;
    data.len = msg->payloadsz;

    njt_stream_proto_python_on_msg(r, data.data, data.len);
    return NJT_OK;
}



int ws_app_on_close(tcc_stream_request_t *r) {

    app_client_t *app_client = tcc_get_client_app_ctx(r);
    if(app_client != NULL) {
        proto_free(r,app_client);
    }
    proto_server_log(NJT_LOG_DEBUG, "tcc from ws_app_on_close!");
    return NJT_OK;
}

int ws_app_client_update(tcc_stream_request_t *r) {
    app_client_t *app_client = tcc_get_client_app_ctx(r);
    tcc_str_t data = njt_string("tcc ws_app_client_update!\n");
    if(app_client != NULL) {
        //ws_send_frame(r, WS_OPCODE_TEXT, data.data, data.len);
        proto_server_log(NJT_LOG_DEBUG, "tcc from ws_app_client_update !");

    }
    return NJT_OK;
}
int ws_app_server_update(tcc_stream_server_ctx *srv_ctx)
{
  tcc_str_t data = njt_string("tcc ws_app_server_update!\n");
  tcc_str_t out_data;
  app_server_t * srv_data = tcc_get_app_srv_ctx(srv_ctx);
  if(srv_data) {
    ws_generate_frame(WS_OPCODE_TEXT, data.data, data.len, &out_data);
    if(out_data.len > 0) {
        free(out_data.data);

    }
  proto_server_log(NJT_LOG_DEBUG, "tcc from ws_app_server_update !");
  }
  return NJT_OK;
}

int ws_app_server_init(tcc_stream_server_ctx *srv_ctx) {
    app_server_t *app_server = proto_malloc(srv_ctx,sizeof(app_server_t));
    if(app_server != NULL) {
        app_server->gen_client_id = 0;
        app_server->server_id = 1;
        tcc_set_app_srv_ctx(srv_ctx,app_server);
    }
    proto_server_log(NJT_LOG_DEBUG, "tcc from ws_app_server_init!");
    return NJT_OK;
}
