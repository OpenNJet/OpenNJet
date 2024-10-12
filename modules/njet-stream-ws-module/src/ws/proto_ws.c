
#include <njt_core.h>
#include "proto_ws.h"
#include <assert.h>
#include <string.h>
#ifdef assert
# define assertFalse(msg) assert(0 && msg)
#else
# define assertFalse(msg)
#endif
#define SET_STATE(V) parser->state = V
#define HAS_DATA() (p < end )
#define CC (*p)
#define GET_NPARSED() ( (p == end) ? len : (p - data) )

#define NOTIFY_CB(FOR)                                                 \
do {                                                                   \
  if (parser->settings->on_##FOR) {                                            \
    if (parser->settings->on_##FOR(parser) != 0) {                             \
      return GET_NPARSED();                                            \
    }                                                                  \
  }                                                                    \
} while (0)

#define EMIT_DATA_CB(FOR, ptr, len)                                    \
do {                                                                   \
  if (parser->settings->on_##FOR) {                                            \
    if (parser->settings->on_##FOR(parser, ptr, len) != 0) {                   \
      return GET_NPARSED();                                            \
    }                                                                  \
  }                                                                    \
} while (0)

enum state {
    s_start,
    s_head,
    s_length,
    s_mask,
    s_body,
};



ssize_t websocket_parser_execute(websocket_parser_t *parser, const char *data, size_t l) {
    const char * p;
    ssize_t len=l;
    const char * end = data + len;
    size_t frame_offset = 0;

    for(p = data; p != end; p++) {
        switch(parser->state) {
            case s_start:
                parser->offset      = 0;
                parser->length      = 0;
                parser->mask_offset = 0;
                parser->flags       = (websocket_flags) (CC & WS_OP_MASK);
                if(CC & (1<<7)) {
                    parser->flags |= WS_FIN;
                }
                SET_STATE(s_head);

                frame_offset++;
                break;
            case s_head:
                parser->length  = (size_t)CC & 0x7F;
                if(CC & 0x80) {
                    parser->flags |= WS_HAS_MASK;
                }
                if(parser->length >= 126) {
                    if(parser->length == 127) {
                        parser->require = 8;
                    } else {
                        parser->require = 2;
                    }
                    parser->length = 0;
                    SET_STATE(s_length);
                } else if (parser->flags & WS_HAS_MASK) {
                    SET_STATE(s_mask);
                    parser->require = 4;
                } else if (parser->length) {
                    SET_STATE(s_body);
                    parser->require = parser->length;
                    NOTIFY_CB(frame_header);
                } else {
                    SET_STATE(s_start);
                    NOTIFY_CB(frame_header);
                    NOTIFY_CB(frame_end);
                     return GET_NPARSED();
                }

                frame_offset++;
                break;
            case s_length:
                while(HAS_DATA() && parser->require) {
                    parser->length <<= 8;
                    parser->length |= (unsigned char)CC;
                    parser->require--;
                    frame_offset++;
                    p++;
                }
                p--;
                if(!parser->require) {
                    if (parser->flags & WS_HAS_MASK) {
                        SET_STATE(s_mask);
                        parser->require = 4;
                    } else if (parser->length) {
                        SET_STATE(s_body);
                        parser->require = parser->length;
                        NOTIFY_CB(frame_header);
                    } else {
                        SET_STATE(s_start);
                        NOTIFY_CB(frame_header);
                        NOTIFY_CB(frame_end);
                         return GET_NPARSED();
                    }
                }
                break;
            case s_mask:
                while(HAS_DATA() && parser->require) {
                    parser->mask[4 - parser->require--] = CC;
                    frame_offset++;
                    p++;
                }
                p--;
                if(!parser->require) {
                    if(parser->length) {
                        SET_STATE(s_body);
                        parser->require = parser->length;
                        NOTIFY_CB(frame_header);
                    } else {
                        SET_STATE(s_start);
                        NOTIFY_CB(frame_header);
                        NOTIFY_CB(frame_end);
                         return GET_NPARSED();
                    }
                }
                break;
              case s_body:
                if(parser->require) {
                    if(p + parser->require <= end) {
                        EMIT_DATA_CB(frame_body, p, parser->require);
                        p += parser->require;
                        parser->require = 0;
                        frame_offset = p - data;
                    } else {
                        EMIT_DATA_CB(frame_body, p, end - p);
                        parser->require -= end - p;
                        p = end;
                        parser->offset += p - data - frame_offset;
                        frame_offset = 0;
                    }

                    //p--;
                    //by stdanley, 
                    //tips: -- cause return 1 byte less consumed data
                    
                }
                if(!parser->require) {
                    NOTIFY_CB(frame_end);
                     return GET_NPARSED();
                    SET_STATE(s_start);
                } else {
                    //by stdanley
                    p--;
                }
                break;
            default:
                assertFalse("Unreachable case");
        }
    }

    return GET_NPARSED();
}


void websocket_parser_decode(char * dst, const char * src, size_t len, websocket_parser_t * parser) {
    size_t i = 0;
    for(; i < len; i++) {
        dst[i] = src[i] ^ parser->mask[(i + parser->mask_offset) % 4];
    }

    parser->mask_offset = (uint8_t) ((i + parser->mask_offset) % 4);
}

uint8_t websocket_decode(char * dst, const char * src, size_t len, const char mask[4], uint8_t mask_offset) {
    size_t i = 0;
    for(; i < len; i++) {
        dst[i] = src[i] ^ mask[(i + mask_offset) % 4];
    }

    return (uint8_t) ((i + mask_offset) % 4);
}

size_t websocket_calc_frame_size(websocket_flags flags, size_t data_len) {
    size_t size = data_len + 2; // body + 2 bytes of head
    if(data_len >= 126) {
        if(data_len > 0xFFFF) {
            size += 8;
        } else {
            size += 2;
        }
    }
    if(flags & WS_HAS_MASK) {
        size += 4;
    }

    return size;
}
void websocket_parser_init(websocket_parser_t * parser,websocket_parser_settings *settings) {
    void *data = parser->data; /* preserve application data */
    memset(parser, 0, sizeof(*parser));
    parser->settings=settings;
    parser->data = data;
    parser->state = s_start;
}
size_t websocket_build_frame(char * frame, websocket_flags flags, const char mask[4], const char * data, size_t data_len) {
    size_t body_offset = 0;
    frame[0] = 0;
    frame[1] = 0;
    if(flags & WS_FIN) {
        frame[0] = (char) (1 << 7);
    }
    frame[0] |= flags & WS_OP_MASK;
    if(flags & WS_HAS_MASK) {
        frame[1] = (char) (1 << 7);
    }
    if(data_len < 126) {
        frame[1] |= data_len;
        body_offset = 2;
    } else if(data_len <= 0xFFFF) {
        frame[1] |= 126;
        frame[2] = (char) (data_len >> 8);
        frame[3] = (char) (data_len & 0xFF);
        body_offset = 4;
    } else {
        frame[1] |= 127;
        frame[2] = (char) ((data_len >> 56) & 0xFF);
        frame[3] = (char) ((data_len >> 48) & 0xFF);
        frame[4] = (char) ((data_len >> 40) & 0xFF);
        frame[5] = (char) ((data_len >> 32) & 0xFF);
        frame[6] = (char) ((data_len >> 24) & 0xFF);
        frame[7] = (char) ((data_len >> 16) & 0xFF);
        frame[8] = (char) ((data_len >>  8) & 0xFF);
        frame[9] = (char) ((data_len)       & 0xFF);
        body_offset = 10;
    }
    if(flags & WS_HAS_MASK) {
        if(mask != NULL) {
            memcpy(&frame[body_offset], mask, 4);
        }
        websocket_decode(&frame[body_offset + 4], data, data_len, &frame[body_offset], 0);
        body_offset += 4;
    } else {
        memcpy(&frame[body_offset], data, data_len);
    }

    return body_offset + data_len;
}
static websocket_parser_settings ws_settings;
static int ws_setting_inited=0;

typedef struct ws_buf_chain_s{
    char* data;
    int   len;
    int opcode;
    int is_final;
    struct ws_buf_chain_s *next;

}ws_buf_chain_t;

typedef struct Websocket_ctx_s {
    njt_pool_t *pool;   
    tcc_stream_request_t *r;
    websocket_parser_t  parser;
    websocket_msg_cb   on_msg;
    
    ws_buf_chain_t  *bufs;
    size_t     bufs_len;
    int        finished;
    ws_buf_chain_t  *iter; 
    
} Websocket_ctx_t;
static  int on_ws_header(websocket_parser_t* parser){
    Websocket_ctx_t* ws_ctx=parser->data;
    ws_buf_chain_t  *p, *q=ws_ctx->bufs;
    p=q;
    while (q) {p=q; q=q->next;}
    q=njt_pcalloc(ws_ctx->pool, sizeof(ws_buf_chain_t));
    ws_ctx->iter=q;
    q->next=NULL;
    q->opcode= parser->flags & WS_OP_MASK; // gets opcode
    q->is_final = parser->flags & WS_FIN;   // checks is final frame
    q->len=0;
    q->data=NULL;
    ws_ctx->iter=q;
    if(parser->length) {
        
        q->len=parser->length;
        ws_ctx->bufs_len+= parser->length;
        q->data=njt_pcalloc(ws_ctx->pool,parser->length);
    }
    if (p) p->next=q;
    else ws_ctx->bufs=q;
    return WS_OK;
};
static  int on_ws_body(websocket_parser_t* parser,const char *at, size_t size){
    Websocket_ctx_t* ws_ctx=parser->data;
    ws_buf_chain_t *p=ws_ctx->bufs;
    while (p->next)p=p->next;
    if(parser->flags & WS_HAS_MASK) {
        // if frame has mask, we have to copy and decode data via websocket_parser_copy_masked function
        websocket_parser_decode(p->data+parser->offset, at, size, parser);
    } else {
        memcpy(p->data+parser->offset, at, size);
    }
    return WS_OK;
};
int on_ws_end(websocket_parser_t * parser) {
    njt_str_t data;
    Websocket_ctx_t* ws_ctx=parser->data;
    if (!ws_ctx->iter->is_final) return 0;
    ws_ctx->finished=1;
    switch (ws_ctx->bufs->opcode)
    {
    case WS_OP_PING:
        /* todo: */
        break;
    case WS_OP_PONG:
        return WS_PAUSED;
    case WS_OP_CLOSE:
         //todo: issue server close
         cli_close(ws_ctx->r);
         return WS_OK;
    default:
        if (ws_ctx->on_msg) {
            if (WS_OK!=ws_ctx->on_msg(ws_ctx->iter->opcode, ws_ctx->bufs_len,ws_ctx->r)) return WS_ERROR;
        } else {
            data.data = (u_char *)ws_ctx->iter->data;
            data.len = ws_ctx->iter->len;
            njt_log_error(NJT_LOG_DEBUG,njt_cycle->log,0,"tcc on_ws_end=%V",&data);
        }
    }
    
    
    
    return WS_PAUSED;
}
static void ws_init_ctx(njt_pool_t *parent_pool,Websocket_ctx_t *ctx);
int ws_init_conn(tcc_stream_request_t *r, websocket_msg_cb msg_cb){
    Websocket_ctx_t* ctx;
    if (!ws_setting_inited) {
        ws_setting_inited =1;
        //websocket_parser_settings_init(&ws_settings);
        ws_settings.on_frame_header=on_ws_header;
        ws_settings.on_frame_body=on_ws_body;
        ws_settings.on_frame_end=on_ws_end;

    }
    ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_WS);
    if(!ctx ) {
            ctx=njt_pcalloc((njt_pool_t *)r->tcc_pool,sizeof(Websocket_ctx_t));
            ws_init_ctx(r->tcc_pool, ctx);
            ctx->r=r;
            ctx->parser.data=ctx;
            tcc_set_client_ctx(r,TCC_PROTO_CTX_WS,ctx);
        }
    ctx->on_msg=msg_cb;
    return WS_OK;
    
    
    
}
static void ws_clear_ctx(Websocket_ctx_t *ctx){
    njt_log_error(NJT_LOG_ERR,njt_cycle->log,0,"clear parser ctx,%p->%p",ctx,ctx->pool);
    if(ctx->pool == NULL) {
        return;
    }
    njt_destroy_pool(ctx->pool);
    ctx->pool=NULL;

}
static void ws_init_ctx(njt_pool_t *parent_pool,Websocket_ctx_t *ctx){
    ctx->pool =njt_create_pool(NJT_MIN_POOL_SIZE,njt_cycle->log); 
    if(ctx->pool) {
        njt_sub_pool(parent_pool,ctx->pool);
    }  
    websocket_parser_init(&ctx->parser, &ws_settings);
    ctx->finished=0;
    ctx->bufs=NULL;
    ctx->bufs_len=0;
    ctx->iter=NULL;
 
}
int  ws_parse(tcc_stream_request_t *r,tcc_str_t *msg) {
    Websocket_ctx_t* ctx;
    char* input_data;
    size_t input_len=msg->len;
    ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_WS);
    input_data=(char*)msg->data; 
    r->used_len=0;

    while (input_len>0) {
        size_t consumed= websocket_parser_execute(&ctx->parser,input_data,input_len);
        r->used_len+=consumed;
        if (consumed==input_len) {
            if (ctx->finished) {
                if(ctx->on_msg) {
                    ws_clear_ctx(ctx);
                    ws_init_ctx(r->tcc_pool,ctx);
                }

                return APP_OK;
            }
            njt_log_error(NJT_LOG_ERR,njt_cycle->log,0,"ws parser ,need more");
            return APP_AGAIN;
        } else {
            if (!ctx->finished) return APP_ERROR;
             return APP_OK;
            ws_clear_ctx(ctx);
            input_data=input_data+consumed;
            input_len-=consumed;
            ws_init_ctx(r->tcc_pool,ctx);
            continue;
        }
    }
    return APP_OK;
}
void ws_iter_start(tcc_stream_request_t *r,size_t *total_len,int *type){
    Websocket_ctx_t *ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_WS);
    if (ctx){
         ctx->iter=ctx->bufs;
         if(ctx->iter != NULL) {
            *type = ctx->iter->opcode;
            *total_len = ctx->bufs_len;
         } else {
            *type = 0;
            *total_len = 0;
         }
    }
}
int  ws_iter_next(tcc_stream_request_t *r, char** buf){
    tcc_str_t data;
    Websocket_ctx_t *ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_WS);

    if (ctx && ctx->iter && ctx->iter->len>0) {
        *buf=ctx->iter->data;
        int len=ctx->iter->len;
        data.data = (u_char *)ctx->iter->data;
        data.len = len;
         proto_server_log(NJT_LOG_INFO,"in ws_iter:%V",&data);
        ctx->iter=ctx->iter->next;
       
        return len;
    }
    return 0;
}
// this is server side send ,no mask needed
int  ws_send(tcc_stream_request_t *r,int type, int length, char* buf, int is_last){
    int ret;
    Websocket_ctx_t *ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_WS);
    websocket_flags flag=type ;
    if (is_last) flag|= WS_FINAL_FRAME;
    size_t frame_len = websocket_calc_frame_size(flag, length);
    char * frame = njt_pcalloc(ctx->pool,frame_len);
    websocket_build_frame(frame,flag,NULL,buf,length);
    
    while (frame_len>0) {
        ret = proto_server_send(r,frame,frame_len);
         proto_server_log(NJT_LOG_INFO,"proto_server_send:%d",ret);
        if (ret<0)         return WS_ERROR;
        frame_len-=ret;
        frame+= ret;
    }
    return WS_OK;
} 
int  ws_iter_has_data(tcc_stream_request_t *r){
    Websocket_ctx_t *ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_WS);

    if (ctx && ctx->iter && ctx->iter->len>0 && ctx->finished) {
        return APP_TRUE;
    }
    return APP_FALSE;
}  
int  ws_destory_ctx(tcc_stream_request_t *r){ 
     Websocket_ctx_t *ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_WS);
    if (ctx) {
       ws_clear_ctx(ctx);
       ws_init_ctx(r->tcc_pool,ctx);
    }
    return APP_TRUE;
}

int  ws_send_broadcast(tcc_stream_request_t *r,int type, int length, char* buf, int is_last){
    int ret;
    Websocket_ctx_t *ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_WS);
    websocket_flags flag=type ;
    if (is_last) flag|= WS_FINAL_FRAME;
    size_t frame_len = websocket_calc_frame_size(flag, length);
    char * frame = njt_pcalloc(ctx->pool,frame_len);
    websocket_build_frame(frame,flag,NULL,buf,length);
    
    while (frame_len>0) {
        ret = proto_server_send_broadcast(r->tcc_server,frame,frame_len);
         proto_server_log(NJT_LOG_INFO,"ws_send_broadcast:%d",ret);
        if (ret<0)         return WS_ERROR;
        frame_len-=ret;
        frame+= ret;
    }
    return WS_OK;
} 
int  ws_send_other(tcc_stream_request_t *r,int type, int length, char* buf, int is_last){
    int ret;
    Websocket_ctx_t *ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_WS);
    websocket_flags flag=type ;
    if (is_last) flag|= WS_FINAL_FRAME;
    size_t frame_len = websocket_calc_frame_size(flag, length);
    char * frame = njt_pcalloc(ctx->pool,frame_len);
    websocket_build_frame(frame,flag,NULL,buf,length);
    
    while (frame_len>0) {
        ret = proto_server_send_others(r,frame,frame_len);
         proto_server_log(NJT_LOG_INFO,"ws_send_other:%d",ret);
        if (ret<0)         return WS_ERROR;
        frame_len-=ret;
        frame+= ret;
    }
    return WS_OK;
} 