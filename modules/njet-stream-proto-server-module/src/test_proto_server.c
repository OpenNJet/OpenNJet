#include <tcc_ws.h>
#include <ctype.h>

// global vari
TccWSHeaders headers; 
typedef struct {
  uint32_t state[5];
  uint32_t count[2];
  uint8_t buffer[64];
} SHA1_CTX;
#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#ifdef LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#else
#define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


#define CRLF "\r\n"
#define WS_MAGIC_STR "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_SWITCH_PROTO_STR "HTTP/1.1 101 Switching Protocols"
#ifndef SHA_DIGEST_LENGTH
    #define SHA_DIGEST_LENGTH 20
#endif

//
void *
xmalloc (size_t size) {
  void *ptr;

  if ((ptr = malloc (size)) == NULL)
    proto_server_log(NJT_LOG_DEBUG,"Unable to allocate memory - failed.");

  return (ptr);
}

char *
xstrdup (const char *s) {
  char *ptr;
  size_t len;

  len = strlen (s) + 1;
  ptr = xmalloc (len);

  strncpy (ptr, s, len);
  return (ptr);
}

/* Self-checking wrapper to calloc() */
void *
xcalloc (size_t nmemb, size_t size) {
  void *ptr;

  if ((ptr = calloc (nmemb, size)) == NULL)
    proto_server_log(NJT_LOG_DEBUG,"Unable to calloc memory - failed.");

  return (ptr);
}

void *
xrealloc (void *oldptr, size_t size) {
  void *newptr;

  if ((newptr = realloc (oldptr, size)) == NULL)
    proto_server_log(NJT_LOG_DEBUG,"Unable to reallocate memory - failed");

  return (newptr);
}


static char *
strtoupper (char *str) {
  char *p = str;
  if (str == NULL || *str == '\0')
    return str;

  while (*p != '\0') {
    *p = toupper ((int) *p);
    p++;
  }

  return str;
}


static const char *
ws_get_method (const char *token) {
  const char *lookfor = NULL;

  if ((lookfor = "GET", !memcmp (token, "GET ", 4)) ||
      (lookfor = "get", !memcmp (token, "get ", 4)))
    return lookfor;
  return NULL;
}


char *
base64_encode (const void *buf, size_t size) {
  static const char base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  char *str = (char *) xmalloc ((size + 3) * 4 / 3 + 1);

  char *p = str;
  const unsigned char *q = (const unsigned char *) buf;
  size_t i = 0;

  while (i < size) {
    int c = q[i++];
    c *= 256;
    if (i < size)
      c += q[i];
    i++;

    c *= 256;
    if (i < size)
      c += q[i];
    i++;

    *p++ = base64[(c & 0x00fc0000) >> 18];
    *p++ = base64[(c & 0x0003f000) >> 12];

    if (i > size + 1)
      *p++ = '=';
    else
      *p++ = base64[(c & 0x00000fc0) >> 6];

    if (i > size)
      *p++ = '=';
    else
      *p++ = base64[c & 0x0000003f];
  }

  *p = 0;

  return str;
}


static void
ws_set_header_key_value (TccWSHeaders *headers, char *key, char *value) {
  if (strcasecmp ("Host", key) == 0)
    headers->host = xstrdup (value);
  else if (strcasecmp ("Origin", key) == 0)
    headers->origin = xstrdup (value);
  else if (strcasecmp ("Upgrade", key) == 0)
    headers->upgrade = xstrdup (value);
  else if (strcasecmp ("Connection", key) == 0)
    headers->connection = xstrdup (value);
  else if (strcasecmp ("Sec-WebSocket-Protocol", key) == 0)
    headers->ws_protocol = xstrdup (value);
  else if (strcasecmp ("Sec-WebSocket-Key", key) == 0)
    headers->ws_key = xstrdup (value);
  else if (strcasecmp ("Sec-WebSocket-Version", key) == 0)
    headers->ws_sock_ver = xstrdup (value);
  else if (strcasecmp ("User-Agent", key) == 0)
    headers->agent = xstrdup (value);
  else if (strcasecmp ("Referer", key) == 0)
    headers->referer = xstrdup (value);
}

static char *
ws_parse_request (char *line, char **method, char **protocol) {
  const char *meth;
  char *req = NULL, *request = NULL, *proto = NULL;
  ptrdiff_t rlen;

  if ((meth = ws_get_method (line)) == NULL) {
    return NULL;
  } else {
    req = line + strlen (meth);
    if ((proto = strstr (line, " HTTP/1.0")) == NULL &&
        (proto = strstr (line, " HTTP/1.1")) == NULL)
      return NULL;

    req++;
    if ((rlen = proto - req) <= 0)
      return NULL;

    request = xmalloc (rlen + 1);
    strncpy (request, req, rlen);
    request[rlen] = 0;

    (*method) = strtoupper (xstrdup (meth));
    (*protocol) = strtoupper (xstrdup (++proto));
  }

  return request;
}

static int
ws_set_header_fields (char *line, TccWSHeaders *headers) {
  char *path = NULL, *method = NULL, *proto = NULL, *p, *value;

  if (line[0] == '\n' || line[0] == '\r')
    return 1;

  if ((strstr (line, "GET ")) || (strstr (line, "get "))) {
    if ((path = ws_parse_request (line, &method, &proto)) == NULL)
      return 1;
    headers->path = path;
    headers->method = method;
    headers->protocol = proto;

    return 0;
  }

  if ((p = strchr (line, ':')) == NULL)
    return 1;

  value = p + 1;
  while (p != line && isspace ((unsigned char) *(p - 1)))
    p--;

  if (p == line)
    return 1;

  *p = '\0';
  if (strpbrk (line, " \t") != NULL) {
    *p = ' ';
    return 1;
  }
  while (isspace ((unsigned char) *value))
    value++;

  ws_set_header_key_value (headers, line, value);

  return 0;
}

static int
parse_headers (TccWSHeaders *headers) {
  char *tmp = NULL;
  const char *buffer = headers->buf;
  const char *line = buffer, *next = NULL;
  int len = 0;

  while (line) {
    if ((next = strstr (line, "\r\n")) != NULL)
      len = (next - line);
    else
      len = strlen (line);

    if (len <= 0)
      return 1;

    tmp = xmalloc (len + 1);
    memcpy (tmp, line, len);
    tmp[len] = '\0';

    if (ws_set_header_fields (tmp, headers) == 1) {
      free (tmp);
      return 1;
    }

    free (tmp);
    line = next ? (next + 2) : NULL;

    if (next && strcmp (next, "\r\n\r\n") == 0)
      break;
  }

  return 0;
}
static int
ws_verify_req_headers (TccWSHeaders *headers) {
  if (!headers->host)
    return 1;
  if (!headers->method)
    return 1;
  if (!headers->protocol)
    return 1;
  if (!headers->path)
    return 1;
  if (!headers->connection)
    return 1;
  if (!headers->ws_key)
    return 1;
  if (!headers->ws_sock_ver)
    return 1;
  return 0;
}
static void
SHA1Init (SHA1_CTX *context) {
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
  context->count[0] = context->count[1] = 0;
}
void
SHA1Transform (uint32_t state[5], uint8_t buffer[64]) {
  uint32_t a, b, c, d, e;
  typedef union {
    uint8_t c[64];
    uint32_t l[16];
  } CHAR64LONG16;
  CHAR64LONG16 *block;
#ifdef SHA1HANDSOFF
  static uint8_t workspace[64];
  block = (CHAR64LONG16 *) (void *) workspace;
  memcpy (block, buffer, 64);
#else
  block = (CHAR64LONG16 *) (void *) buffer;
#endif
  /* Copy context->state[] to working vars */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  /* 4 rounds of 20 operations each. Loop unrolled. */
  R0 (a, b, c, d, e, 0);
  R0 (e, a, b, c, d, 1);
  R0 (d, e, a, b, c, 2);
  R0 (c, d, e, a, b, 3);
  R0 (b, c, d, e, a, 4);
  R0 (a, b, c, d, e, 5);
  R0 (e, a, b, c, d, 6);
  R0 (d, e, a, b, c, 7);
  R0 (c, d, e, a, b, 8);
  R0 (b, c, d, e, a, 9);
  R0 (a, b, c, d, e, 10);
  R0 (e, a, b, c, d, 11);
  R0 (d, e, a, b, c, 12);
  R0 (c, d, e, a, b, 13);
  R0 (b, c, d, e, a, 14);
  R0 (a, b, c, d, e, 15);
  R1 (e, a, b, c, d, 16);
  R1 (d, e, a, b, c, 17);
  R1 (c, d, e, a, b, 18);
  R1 (b, c, d, e, a, 19);
  R2 (a, b, c, d, e, 20);
  R2 (e, a, b, c, d, 21);
  R2 (d, e, a, b, c, 22);
  R2 (c, d, e, a, b, 23);
  R2 (b, c, d, e, a, 24);
  R2 (a, b, c, d, e, 25);
  R2 (e, a, b, c, d, 26);
  R2 (d, e, a, b, c, 27);
  R2 (c, d, e, a, b, 28);
  R2 (b, c, d, e, a, 29);
  R2 (a, b, c, d, e, 30);
  R2 (e, a, b, c, d, 31);
  R2 (d, e, a, b, c, 32);
  R2 (c, d, e, a, b, 33);
  R2 (b, c, d, e, a, 34);
  R2 (a, b, c, d, e, 35);
  R2 (e, a, b, c, d, 36);
  R2 (d, e, a, b, c, 37);
  R2 (c, d, e, a, b, 38);
  R2 (b, c, d, e, a, 39);
  R3 (a, b, c, d, e, 40);
  R3 (e, a, b, c, d, 41);
  R3 (d, e, a, b, c, 42);
  R3 (c, d, e, a, b, 43);
  R3 (b, c, d, e, a, 44);
  R3 (a, b, c, d, e, 45);
  R3 (e, a, b, c, d, 46);
  R3 (d, e, a, b, c, 47);
  R3 (c, d, e, a, b, 48);
  R3 (b, c, d, e, a, 49);
  R3 (a, b, c, d, e, 50);
  R3 (e, a, b, c, d, 51);
  R3 (d, e, a, b, c, 52);
  R3 (c, d, e, a, b, 53);
  R3 (b, c, d, e, a, 54);
  R3 (a, b, c, d, e, 55);
  R3 (e, a, b, c, d, 56);
  R3 (d, e, a, b, c, 57);
  R3 (c, d, e, a, b, 58);
  R3 (b, c, d, e, a, 59);
  R4 (a, b, c, d, e, 60);
  R4 (e, a, b, c, d, 61);
  R4 (d, e, a, b, c, 62);
  R4 (c, d, e, a, b, 63);
  R4 (b, c, d, e, a, 64);
  R4 (a, b, c, d, e, 65);
  R4 (e, a, b, c, d, 66);
  R4 (d, e, a, b, c, 67);
  R4 (c, d, e, a, b, 68);
  R4 (b, c, d, e, a, 69);
  R4 (a, b, c, d, e, 70);
  R4 (e, a, b, c, d, 71);
  R4 (d, e, a, b, c, 72);
  R4 (c, d, e, a, b, 73);
  R4 (b, c, d, e, a, 74);
  R4 (a, b, c, d, e, 75);
  R4 (e, a, b, c, d, 76);
  R4 (d, e, a, b, c, 77);
  R4 (c, d, e, a, b, 78);
  R4 (b, c, d, e, a, 79);
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  a = b = c = d = e = 0;
}

static void
SHA1Update (SHA1_CTX *context, uint8_t *data, unsigned int len) {
  unsigned int i, j;

  j = (context->count[0] >> 3) & 63;
  if ((context->count[0] += len << 3) < (len << 3))
    context->count[1]++;
  context->count[1] += (len >> 29);
  if ((j + len) > 63) {
    memcpy (&context->buffer[j], data, (i = 64 - j));
    SHA1Transform (context->state, context->buffer);
    for (; i + 63 < len; i += 64) {
      SHA1Transform (context->state, &data[i]);
    }
    j = 0;
  } else
    i = 0;
  memcpy (&context->buffer[j], &data[i], len - i);
}

static void
SHA1Final (uint8_t digest[20], SHA1_CTX *context) {
  uint32_t i, j;
  uint8_t finalcount[8];

  for (i = 0; i < 8; i++) {
    finalcount[i] = (uint8_t) ((context->count[(i >= 4 ? 0 : 1)]
                                >> ((3 - (i & 3)) * 8)) & 255); /* Endian independent */
  }
  SHA1Update (context, (uint8_t *) "\200", 1);
  while ((context->count[0] & 504) != 448) {
    SHA1Update (context, (uint8_t *) "\0", 1);
  }
  SHA1Update (context, finalcount, 8);  /* Should cause a SHA1Transform() */
  for (i = 0; i < 20; i++) {
    digest[i] = (uint8_t)
      ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
  }
  /* Wipe variables */
  i = j = 0;
  memset (context->buffer, 0, 64);
  memset (context->state, 0, 20);
  memset (context->count, 0, 8);
  memset (&finalcount, 0, 8);
#ifdef SHA1HANDSOFF     /* make SHA1Transform overwrite its own static vars */
  SHA1Transform (context->state, context->buffer);
#endif
}
static void
ws_sha1_digest (char *s, int len, unsigned char *digest) {
  SHA1_CTX sha;

  SHA1Init (&sha);
  SHA1Update (&sha, (uint8_t *) s, len);
  SHA1Final (digest, &sha);
}

static void
ws_set_handshake_headers (TccWSHeaders *headers) {
 
  size_t klen = strlen (headers->ws_key);
  size_t mlen = strlen (WS_MAGIC_STR);
  size_t len = klen + mlen;
  char *s = xmalloc (klen + mlen + 1);
  uint8_t digest[SHA_DIGEST_LENGTH];

  memset (digest, 0, sizeof *digest);

  memcpy (s, headers->ws_key, klen);
  memcpy (s + klen, WS_MAGIC_STR, mlen + 1);

  ws_sha1_digest (s, len, digest);


  headers->ws_accept = base64_encode ((unsigned char *) digest, sizeof (digest));
  headers->ws_resp = xstrdup (WS_SWITCH_PROTO_STR);

  if (!headers->upgrade)
    headers->upgrade = xstrdup ("websocket");
  if (!headers->connection)
    headers->connection = xstrdup ("Upgrade");

  free (s);
  

}
static void
ws_append_str (char **dest, const char *src) {
  size_t curlen = strlen (*dest);
  size_t srclen = strlen (src);
  size_t newlen = curlen + srclen;

  char *str = xrealloc (*dest, newlen + 1);
  memcpy (str + curlen, src, srclen + 1);
  *dest = str;
}

static int
ws_send_handshake_headers (tcc_stream_request_t *r, TccWSHeaders *headers) {
  int bytes = 0;
  char *str = xstrdup ("");

  ws_append_str (&str, headers->ws_resp);
  ws_append_str (&str, CRLF);
  ws_append_str (&str, "Upgrade: ");
  ws_append_str (&str, headers->upgrade);
  ws_append_str (&str, CRLF);
  ws_append_str (&str, "Connection: ");
  ws_append_str (&str, headers->connection);
  ws_append_str (&str, CRLF);
  ws_append_str (&str, "Sec-WebSocket-Accept: ");
  ws_append_str (&str, headers->ws_accept);
  ws_append_str (&str, CRLF CRLF);

  bytes = proto_server_send (r, str, strlen (str));
  free (str);
  return bytes;
}


int proto_server_process_connetion(tcc_stream_request_t *r) {
    char buffer[1024] = {0};
    char ip[64] = "127.0.0.1"; 
    int ret;
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);
    ret = memcmp((void *)r->addr_text->data,ip,strlen(ip));

    if(memcmp((void *)r->addr_text->data,ip,strlen(ip)) == 0) {
	proto_server_log(NJT_LOG_DEBUG,"1 tcc connetion ip=%s,NJT_STREAM_FORBIDDEN !",p);
	free(p);
	return NJT_STREAM_FORBIDDEN;
    } 
    proto_server_log(NJT_LOG_DEBUG,"1 tcc connetion ip=%s ok!",p);
    free(p);
    return NJT_OK;
}
int proto_server_process_preread(tcc_stream_request_t *r) {
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);
    proto_server_log(NJT_LOG_DEBUG,"2 tcc preread ip=%s ok!",p);
    free(p);
    return NJT_DECLINED;
}
int proto_server_process_log(tcc_stream_request_t *r) {
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);
    proto_server_log(NJT_LOG_DEBUG,"4 tcc log ip=%s ok!",p);
    free(p);
    return NJT_OK;
}
int proto_server_process_message(tcc_stream_request_t *r) {
    char buf[1024] = {0};
    char *data = NULL;
    WSctx *cli_ctx;
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);

    proto_server_log(NJT_LOG_DEBUG,"3 tcc content tcc get=%s,len=%d",r->in_buf.pos,r->in_buf.last - r->in_buf.pos);
    snprintf(buf,sizeof(buf),"ret:ip=%s,data=%s\n",p,r->in_buf.pos);
    
    if(r->cli_ctx == NULL) {
        r->cli_ctx = cli_calloc(r,sizeof(WSctx));
    }
    cli_ctx = r->cli_ctx;
    if (cli_ctx->handshake == 0) {
      
        memset(&headers,0,sizeof(headers));
        headers.buflen = r->in_buf.last - r->in_buf.pos;
         
        memcpy(headers.buf,r->in_buf.pos,headers.buflen);
        headers.buf[headers.buflen] = '\0';
 
        data = headers.buf;
        
        if (strstr (data, "\r\n\r\n") == NULL) {
           return NJT_AGAIN; 
        }
        if (parse_headers (&headers) != 0){

        }
        if (ws_verify_req_headers (&headers) != 0) {

        }
        ws_set_handshake_headers (&headers);
        ws_send_handshake_headers(r,&headers);
        
        cli_ctx->handshake = WS_HANDSHAKE_OK;
        
        
    }
    
    //proto_server_send_broadcast(r->srv_ctx,buf,strlen(buf));
    free(p);
    return NJT_OK;
}
int proto_server_process_client_update(tcc_stream_request_t *r) {
    char buf[1024] = {0};
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);
    if (r->in_buf.last != r->in_buf.pos) {
    snprintf(buf,sizeof(buf),"ret:tcc client  update ip=%s,data %s\n",p,r->in_buf.pos);
    } else {
	snprintf(buf,sizeof(buf),"ret:tcc client update ip=%s\n",p);
    }
    //proto_server_send(r,buf,strlen(buf));
    //proto_server_send_broadcast(r->srv_ctx,buf,strlen(buf));

    proto_server_log(NJT_LOG_DEBUG,"%s",buf);
    free(p);
    return NJT_OK;
}

int proto_server_process_connection_abort(tcc_stream_request_t *r) {
    return NJT_OK;
}
int proto_server_update(tcc_stream_server_ctx *srv_ctx) {
   char buf[1024] = "server data\n";
   //proto_server_send_broadcast(srv_ctx,buf,strlen(buf));
   proto_server_log(NJT_LOG_DEBUG,"tcc server update!");
   return NJT_OK;
}
