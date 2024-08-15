#ifndef NJT_TCC_H
#define NJT_TCC_H
#include <arpa/inet.h>
#define  TCC_SESSION_CONNECT  0
#define  TCC_SESSION_CLOSING  1
#define  TCC_SESSION_CLOSED   2

#define njt_string(str)     { sizeof(str) - 1, (u_char *) str }
#define tcc_get_client_ctx(r)   (r)->cli_ctx
#define tcc_set_client_ctx(r, c)  (r)->cli_ctx = c;
#define tcc_client_get_srv_ctx(r)   (r)->tcc_server->srv_data

#define tcc_get_client_app_ctx(r)   (r)->cli_app_ctx
#define tcc_set_client_app_ctx(r, c)  (r)->cli_app_ctx = c;

#define tcc_client_get_app_srv_ctx(r)   (r)->tcc_server->srv_app_ctx

#define tcc_set_srv_ctx(s,c)   (s)->srv_data = c;
#define tcc_get_srv_ctx(s)     (s)->srv_data

#define tcc_set_app_srv_ctx(s,c)   (s)->srv_app_ctx = c;
#define tcc_get_app_srv_ctx(s)   (s)->srv_app_ctx



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

typedef struct tcc_stream_request_s tcc_stream_request_t;
typedef struct tcc_stream_server_ctx_s tcc_stream_server_ctx;
typedef struct tcc_chain_s tcc_chain_t;

typedef intptr_t        tcc_int_t;
typedef uintptr_t       tcc_uint_t;
typedef intptr_t        tcc_flag_t;

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

struct tcc_chain_s
{
  tcc_buf_t *buf;
  tcc_chain_t *next;
};

typedef struct
{
  tcc_int_t num;
  size_t size;
} tcc_bufs_t;
typedef struct {
    size_t      len;
    u_char     *data;
} tcc_str_t;
struct tcc_stream_server_ctx_s
{
  void *client_list;
  void *srv_data;
  void *srv_app_ctx;
  void *tcc_pool;
};

struct tcc_stream_request_s
{
  void *s;
  void *tcc_pool;
  tcc_buf_t  in_buf;
  tcc_str_t  *addr_text;
  void *cli_ctx;
  void *cli_app_ctx;
  tcc_stream_server_ctx *tcc_server;
  int   status;
  int used_len;
};

extern void * cli_malloc(tcc_stream_request_t *r,int len);
extern void cli_free(tcc_stream_request_t *r,void *p);
extern tcc_str_t cli_get_variable(tcc_stream_request_t *r,char *name);
extern void cli_close(tcc_stream_request_t *r);
extern void *cli_realloc(tcc_stream_request_t *r,void *p,int len);

extern void *srv_malloc(tcc_stream_server_ctx *srv,int len);
extern void srv_free(tcc_stream_server_ctx *srv,void *p);
extern void * srv_realloc(tcc_stream_server_ctx *srv,void *p,int len);

extern void proto_server_log(int level,const char *fmt, ...);
extern int proto_server_process_connetion(tcc_stream_request_t *r);
extern int proto_server_process_preread(tcc_stream_request_t *r,tcc_str_t *msg);
extern int proto_server_process_log(tcc_stream_request_t *r);
extern int proto_server_process_message(tcc_stream_request_t *r,tcc_str_t *msg);
extern int proto_server_process_connection_close(tcc_stream_request_t *r);
extern int proto_server_send(tcc_stream_request_t *r,char *data,size_t len);
extern int proto_server_send_broadcast(tcc_stream_server_ctx *srv_ctx,char *data,size_t len);
extern int proto_server_send_others(tcc_stream_request_t *sender, char *data, size_t len);
extern u_char * njt_snprintf(u_char *buf, size_t max, const char *fmt, ...);
#endif
