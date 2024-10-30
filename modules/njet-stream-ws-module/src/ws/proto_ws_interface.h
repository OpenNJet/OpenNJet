#ifndef NJT_PROTO_WS_INTERFACE_H_
#define NJT_PROTO_WS_INTERFACE_H_

#include "njt_tcc.h"

#define WS_SWITCH_PROTO_STR "HTTP/1.1 101 Switching Protocols\r\n"
#define WS_MAGIC_STR "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef enum websocket_flags {
    // opcodes
    WS_OP_CONTINUE = 0x0,
    WS_OP_TEXT     = 0x1,
    WS_OP_BINARY   = 0x2,
    WS_OP_CLOSE    = 0x8,
    WS_OP_PING     = 0x9,
    WS_OP_PONG     = 0xA,

    // marks
    WS_FINAL_FRAME = 0x10,
    WS_HAS_MASK    = 0x20,
} websocket_flags;

typedef enum websocket_errno {
    WS_OK=0,
    WS_PAUSED=1,
    WS_ERROR=-1
} websocket_errno;

typedef int (*websocket_msg_cb) (int type, size_t length,tcc_stream_request_t *r);



// evt: "on_msg" : websocket_msg_cb
 
extern int  ws_init_conn(tcc_stream_request_t *r, websocket_msg_cb msg_cb);
extern int  ws_parse(tcc_stream_request_t *r,tcc_str_t *msg);

extern void ws_iter_start(tcc_stream_request_t *r,size_t *total_len,int *type);
extern int  ws_iter_next(tcc_stream_request_t *r, char** buf);
extern int  ws_send(tcc_stream_request_t *r,int type, int length, char* buf,int is_last);
extern int  ws_iter_has_data(tcc_stream_request_t *r);
extern int  ws_destory_ctx(tcc_stream_request_t *r);
extern int  ws_send_broadcast(tcc_stream_request_t *r,int type, int length, char* buf, int is_last);
extern int  ws_send_other(tcc_stream_request_t *r,int type, int length, char* buf, int is_last);
extern int  ws_close(tcc_stream_request_t *r,int code,int msg_len, char* msg);
extern int  ws_sendto(tcc_stream_server_ctx *srv_ctx,tcc_str_t  *receiver_session,int type, int length, char* buf, int is_last);
#endif