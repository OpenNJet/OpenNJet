#ifndef NJT_TCC_H
#define NJT_TCC_H


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
  void *tcc_pool;
};

struct tcc_stream_request_s
{
  void *s;
  void *tcc_pool;
  tcc_buf_t  in_buf;
  tcc_str_t  *addr_text;
  void *cli_ctx;
  void *srv_ctx;
  unsigned         closed:1;
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
extern int proto_server_process_preread(tcc_stream_request_t *r,tcc_str_t *msg,size_t *used_len);
extern int proto_server_process_log(tcc_stream_request_t *r);
extern int proto_server_process_message(tcc_stream_request_t *r,tcc_str_t *msg,size_t *used_len);
extern int proto_server_process_connection_abort(tcc_stream_request_t *r);
extern int proto_server_send(tcc_stream_request_t *r,char *data,size_t len);
extern int proto_server_send_broadcast(tcc_stream_server_ctx *srv_ctx,char *data,size_t len);
extern u_char * njt_snprintf(u_char *buf, size_t max, const char *fmt, ...);
#endif
