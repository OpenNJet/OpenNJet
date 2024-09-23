#include "llhttp.h"

#include "njt_core.h"
#include "proto_http_interface.h"

typedef struct proto_http_buf_chain_s{
    char* data;
    int   len;
    struct proto_http_buf_chain_s *next;

}proto_http_buf_chain_t;


typedef struct util_http_ctx_s {
    proto_http_buf_chain_t *k;
    int k_l;
    proto_http_buf_chain_t *v;
    int v_l;
    llhttp_t parser;
    proto_http_on_header on_header;
    proto_http_on_body   on_body;
    proto_http_req       on_req;
    njt_pool_t *pool;   //ctx->pool's life cycle existing during a whole http request parse
    tcc_stream_request_t *r;
    char * input_data;
    int finished;
} util_http_ctx_t;

static llhttp_settings_t settings;
static int setting_inited=0;

static  int on_header_key(llhttp_t *parser, const char *buf, size_t len){
    util_http_ctx_t *ctx=parser->data;
    proto_http_buf_chain_t *p, *q=ctx->k;
    p=q;
    while (q) {p=q; q=q->next;}
    q=njt_pcalloc(ctx->pool, sizeof(proto_http_buf_chain_t));
    q->next=NULL;
    q->len=len;
    ctx->k_l+= len;
    q->data=njt_pcalloc(ctx->pool,len);
    memcpy(q->data,buf,len);
    if (p==NULL) { ctx->k=q;} else {p->next=q;};
    return 0;
}
static  int on_header_val(llhttp_t *parser, const char *buf, size_t len){
    util_http_ctx_t *ctx=parser->data;
    proto_http_buf_chain_t *p, *q=ctx->v;
    p=q;
    while (q) {p=q; q=q->next;}
    q=njt_pcalloc(ctx->pool, sizeof(proto_http_buf_chain_t));
    q->next=NULL;
    q->len=len;
    ctx->v_l+= len;

    q->data=njt_pcalloc(ctx->pool,len);
    memcpy(q->data,buf,len);
    if (p==NULL) { ctx->v=q;} else {p->next=q;};
    return 0;
}
static int on_val_done(llhttp_t *parser){
    char *key, *val, *tail;
    proto_http_buf_chain_t *p,*q;
    util_http_ctx_t *ctx=parser->data;
    key=njt_pcalloc(ctx->pool,ctx->k_l+1);
    p=ctx->k;
    tail= key;
    while(p) {
        tail=memcpy(tail,p->data,p->len);
        tail+=p->len;
        p=p->next;
    }

    q=ctx->v;
    val=njt_pcalloc(ctx->pool,ctx->v_l+1);
    tail= val;
    while(q) {
        tail=memcpy(tail,q->data,q->len);
        tail+=q->len;
        q=q->next;
    }
    int ret=ctx->on_header(key,ctx->k_l,val,ctx->v_l,ctx->r);

    ctx->v_l=0;
    ctx->k_l=0;
    ctx->k=NULL;
    ctx->v=NULL;

    return ret;
}

static  int on_msg_done(llhttp_t *parser){

    util_http_ctx_t *ctx=parser->data;
    njt_log_error(NJT_LOG_ERR,njt_cycle->log,0,"on msg done");
    ctx->finished=1;

    if (ctx->on_req) ctx->on_req(ctx->r);
    return HPE_PAUSED;

}
static void tcc_util_http_clear_ctx(util_http_ctx_t *ctx){
    njt_log_error(NJT_LOG_ERR,njt_cycle->log,0,"clear parser ctx,%p->%p",ctx,ctx->pool);
    njt_destroy_pool(ctx->pool);
    ctx->pool=NULL;

}
static void tcc_util_http_init_ctx(util_http_ctx_t *ctx){
    ctx->pool =njt_create_pool(NJT_MIN_POOL_SIZE,njt_cycle->log);   
    ctx->k=NULL;
    ctx->v=NULL;
    ctx->k_l=0;
    ctx->v_l=0;
    ctx->finished=0;
}
int  proto_http_init(tcc_stream_request_t *r,proto_http_on_header on_header,proto_http_on_body on_body, proto_http_req on_req){
    util_http_ctx_t *ctx;
    if (!setting_inited) {
        setting_inited =1;
        llhttp_settings_init(&settings);
        settings.on_header_field=on_header_key;
        settings.on_header_value_complete=on_val_done;
        settings.on_header_value=on_header_val;
        settings.on_message_complete=on_msg_done;
    }
    ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_HTTP);
    if(!ctx ) {
        ctx=njt_pcalloc((njt_pool_t* )r->tcc_pool,sizeof(util_http_ctx_t));
        llhttp_init(&ctx->parser, HTTP_REQUEST, &settings); 
        ctx->parser.data=ctx;
        ctx->r=r;
        ctx->on_header=on_header;
        ctx->on_body=on_body;
        ctx->on_req= on_req;
        tcc_util_http_init_ctx(ctx);
        tcc_set_client_ctx(r,TCC_PROTO_CTX_HTTP,ctx);
    }
    return APP_OK;
}

int  proto_http_parse(tcc_stream_request_t *r,tcc_str_t *msg){
    util_http_ctx_t *ctx;
    enum llhttp_errno err;
    size_t input_len=msg->len;
    
    ctx=tcc_get_client_ctx(r,TCC_PROTO_CTX_HTTP);
    ctx->input_data=(char*)msg->data; 
    r->used_len=0;

    while (input_len>0) {
        
        err= llhttp_execute(&ctx->parser,ctx->input_data,input_len);
        
        switch (err) {
            case HPE_OK: {
                njt_log_error(NJT_LOG_ERR,njt_cycle->log,0, "Parse end: consumed,%d ,need more", input_len);
                r->used_len+=input_len;
                return APP_AGAIN;
            }
            case HPE_PAUSED: {
                //tips: on req parsed , return HPE_PAUSED,so ok means not a full req
                if (1== ctx->finished){
                    const char *last_parsed_pos = llhttp_get_error_pos(&ctx->parser);
                    size_t consumed=last_parsed_pos-ctx->input_data;
                    njt_log_error(NJT_LOG_ERR,njt_cycle->log,0, "Parse one request,consumed:%d",consumed);
                    r->used_len+= consumed;
                    input_len-=consumed;

                    tcc_util_http_clear_ctx(ctx);
                    if (input_len>0) {
                        tcc_util_http_init_ctx(ctx); 
                        //ctx->consumed=0;
                        ctx->input_data= (char*)last_parsed_pos;
                        llhttp_resume(&ctx->parser);
                        continue;
                    } 
                return APP_OK;
                }
            }
            default: {
                njt_log_error(NJT_LOG_ERR,njt_cycle->log,0, "Parse err ,%s %s", llhttp_errno_name(ctx->parser.error), ctx->parser.reason);
                tcc_util_http_clear_ctx(ctx);
                return APP_ERROR;
            }
        }
    
    }
    return APP_AGAIN;

}

