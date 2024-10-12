#ifndef NJT_TCC_H
#define NJT_TCC_H
#include <arpa/inet.h>
#define  TCC_SESSION_CONNECT  0
#define  TCC_SESSION_CLOSING  1
#define  TCC_SESSION_CLOSED   2
#define  TCC_MAX_PROTO_CTX   128
#define  TCC_PROTO_CTX_ID    0

#define njt_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
    
#define njt_string(str)     { sizeof(str) - 1, (u_char *) str }
#define tcc_get_client_ctx(r, module_id)                    \
    (module_id <  TCC_MAX_PROTO_CTX?                                 \
            r->cli_ctx[module_id]:                                    \
        NULL)

#define tcc_set_client_ctx(r,module_id,c)                    \
    (module_id <  TCC_MAX_PROTO_CTX?                                 \
            r->cli_ctx[module_id] = c:                                    \
        NULL)

#define tcc_client_get_srv_ctx(r)   (r)->tcc_server->srv_data

#define tcc_get_client_app_ctx(r)   (r)->cli_app_ctx
#define tcc_set_client_app_ctx(r, c)  (r)->cli_app_ctx = c;

#define tcc_client_get_app_srv_ctx(r)   (r)->tcc_server->srv_app_ctx

#define tcc_set_srv_ctx(s,c)   (s)->srv_data = c;
#define tcc_get_srv_ctx(s)     (s)->srv_data

#define tcc_set_app_srv_ctx(s,c)   (s)->srv_app_ctx = c;
#define tcc_get_app_srv_ctx(s)   (s)->srv_app_ctx

#define tcc_set_peer_srv_ctx(ctx,c)   (ctx)->peer_data = c;
#define tcc_get_peer_srv_ctx(ctx)   (ctx)->peer_data

#define  NJT_LOG_ERR          4
#define  NJT_LOG_DEBUG        8
#define  NJT_LOG_INFO         7
#define  NJT_OK          0
#define  NJT_ERROR          -1
#define  NJT_AGAIN   -2
#define  NJT_DECLINED   -5
#define NJT_STREAM_OK                        200
#define NJT_STREAM_SPECIAL_RESPONSE          300
#define NJT_STREAM_BAD_REQUEST               400
#define NJT_STREAM_FORBIDDEN                 403
#define NJT_STREAM_INTERNAL_SERVER_ERROR     500
#define NJT_STREAM_BAD_GATEWAY               502
#define NJT_STREAM_SERVICE_UNAVAILABLE       503
#define GET_BIT(x,bit)  ((x & (1 << bit)) >> bit)
#define njt_memzero(buf, n)       (void) memset(buf, 0, n)
#define njt_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define njt_memcmp(s1, s2, n)     memcmp(s1, s2, n)

#define njt_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define njt_base64_decoded_length(len)  (((len + 3) / 4) * 3)

#define  APP_OK          0
#define  APP_TRUE        1
#define  APP_FALSE       0
#define  APP_ERROR          -1
#define  APP_AGAIN   -2
#define  APP_DECLINED   -5

typedef struct tcc_stream_request_s tcc_stream_request_t;
typedef struct tcc_stream_server_ctx_s tcc_stream_server_ctx;
typedef struct tcc_stream_upstream_rr_peer_s tcc_stream_upstream_rr_peer_t;
typedef struct tcc_stream_client_upstream_data_s tcc_stream_client_upstream_data_t;


typedef intptr_t        tcc_int_t;
typedef uintptr_t       tcc_uint_t;
typedef intptr_t        tcc_flag_t;
typedef tcc_uint_t      tcc_msec_t;

typedef intptr_t        njt_int_t;

typedef void *tcc_buf_tag_t;
typedef void *tcc_file_t;

typedef struct tcc_buf_s tcc_buf_t;
struct tcc_buf_s
{
  u_char *pos;
  u_char *last;
  off_t file_pos;
  off_t file_last;

  u_char *start; /* start of buffer */
  u_char *end;   /* end of buffer */
  tcc_buf_tag_t tag;
  tcc_file_t *file;
  tcc_buf_t *shadow;

  /* the buf's content could be changed */
  unsigned temporary : 1;

  /*
   * the buf's content is in a memory cache or in a read only memory
   * and must not be changed
   */
  unsigned memory : 1;

  /* the buf's content is mmap()ed and must not be changed */
  unsigned mmap : 1;

  unsigned recycled : 1;
  unsigned in_file : 1;
  unsigned flush : 1;
  unsigned sync : 1;
  unsigned last_buf : 1;
  unsigned last_in_chain : 1;

  unsigned last_shadow : 1;
  unsigned temp_file : 1;

  /* STUB */ int num;
};
typedef struct {
    size_t      len;
    u_char     *data;
} tcc_str_t;


struct tcc_stream_server_ctx_s
{
   /* the tcc_pool data must be first */
  void *tcc_pool; 
  void *client_list;
  void *srv_data;
  void *srv_app_ctx;
  
};
struct tcc_stream_upstream_rr_peer_s
{
    tcc_str_t                        *name;
    tcc_str_t                        *server;
    void                             *peer;
};
struct tcc_stream_client_upstream_data_s
{
  tcc_str_t  *cli_addr_text;
  int peer_num;
  tcc_stream_upstream_rr_peer_t *peer_list;
  
};

struct tcc_stream_request_s
{
  /* the tcc_pool data must be first */
  void *tcc_pool; 
  void *s;
  tcc_buf_t  in_buf;
  size_t session_max_mem_size;
  size_t session_up_max_mem_size;
  tcc_str_t  *addr_text;
  void *cli_ctx[TCC_MAX_PROTO_CTX];
  void *cli_app_ctx;
  tcc_stream_server_ctx *tcc_server;
  int   status;
  int used_len;
};
typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d, e, f;
    u_char    buffer[64];
} tcc_sha1_t;


extern tcc_str_t cli_get_variable(tcc_stream_request_t *r,char *name);
extern void cli_close(tcc_stream_request_t *r);
extern void proto_server_log(int level,const char *fmt, ...);
extern int proto_server_process_connection(tcc_stream_request_t *r);
extern int proto_server_process_preread(tcc_stream_request_t *r,tcc_str_t *msg);
extern int proto_server_process_log(tcc_stream_request_t *r);
extern int proto_server_process_message(tcc_stream_request_t *r,tcc_str_t *msg);
extern int proto_server_process_connection_close(tcc_stream_request_t *r);
extern int proto_server_send(tcc_stream_request_t *r,char *data,size_t len);
extern int proto_server_send_broadcast(tcc_stream_server_ctx *srv_ctx,char *data,size_t len);
extern int proto_server_send_others(tcc_stream_request_t *sender, char *data, size_t len);
extern u_char * njt_snprintf(u_char *buf, size_t max, const char *fmt, ...);
extern void *proto_malloc(void *ctx, int len);
extern void proto_free(void *ctx, void *p);
extern void *proto_realloc(void *ctx, void *p, int len);
extern tcc_int_t proto_get_peer_weight(void *peer);
extern tcc_int_t proto_get_peer_conns(void *peer);
extern tcc_uint_t proto_get_peer_fails(void *peer);
extern int proto_server_send_upstream(tcc_stream_request_t *r,char *data, size_t len);
extern void tcc_encode_base64(tcc_str_t *dst, tcc_str_t *src);
extern void tcc_encode_base64url(tcc_str_t *dst, tcc_str_t *src);
extern tcc_int_t tcc_decode_base64(tcc_str_t *dst, tcc_str_t *src);
extern tcc_int_t tcc_decode_base64url(tcc_str_t *dst, tcc_str_t *src);
extern void tcc_sha1_init(tcc_sha1_t *ctx);
extern void tcc_sha1_update(tcc_sha1_t *ctx, const void *data, size_t size);
extern void tcc_sha1_final(u_char result[20], tcc_sha1_t *ctx);
extern u_char *njt_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);
extern int proto_server_build_message(tcc_stream_request_t *r, void *in_data, tcc_str_t *out_data);
extern int njt_stream_proto_python_on_msg(tcc_stream_request_t *r, char *msg, size_t msg_len);
extern int proto_destroy_pool(void *pool);
extern u_char* proto_util_sha1(tcc_stream_request_t *r,  u_char* src , size_t len, size_t dst_len);
extern void proto_util_base64(tcc_stream_request_t *r, u_char* s , size_t s_l, u_char** dst, size_t *d_l);
extern int proto_server_send_broadcast(tcc_stream_server_ctx *srv_ctx, char *data, size_t len);
int proto_server_send_others(tcc_stream_request_t *sender, char *data, size_t len);
int tcc_sleep(unsigned int seconds);

#endif
