#include <tcc_ws.h>
#include <ctype.h>

static int
ws_send_frame(WSClient *client, WSOpcode opcode, const char *p, int sz);
static int
ws_generate_frame(WSOpcode opcode, const char *p, int sz, tcc_str_t *out_message);

// global vari
int max_frm_size = 6553500;
TccWSHeaders headers;
typedef struct
{
  uint32_t state[5];
  uint32_t count[2];
  uint8_t buffer[64];
} SHA1_CTX;
#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#ifdef LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) | (rol(block->l[i], 8) & 0x00FF00FF))
#else
#define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ block->l[(i + 8) & 15] ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i)                                   \
  z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); \
  w = rol(w, 30);
#define R1(v, w, x, y, z, i)                                  \
  z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); \
  w = rol(w, 30);
#define R2(v, w, x, y, z, i)                          \
  z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); \
  w = rol(w, 30);
#define R3(v, w, x, y, z, i)                                        \
  z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
  w = rol(w, 30);
#define R4(v, w, x, y, z, i)                          \
  z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
  w = rol(w, 30);

#define CRLF "\r\n"
#define WS_MAGIC_STR "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_SWITCH_PROTO_STR "HTTP/1.1 101 Switching Protocols"
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

//
void *
xmalloc(size_t size)
{
  void *ptr;

  if ((ptr = malloc(size)) == NULL)
    proto_server_log(NJT_LOG_DEBUG, "Unable to allocate memory - failed.");

  return (ptr);
}

char *
xstrdup(const char *s)
{
  char *ptr;
  size_t len;

  len = strlen(s) + 1;
  ptr = xmalloc(len);

  strncpy(ptr, s, len);
  return (ptr);
}

/* Self-checking wrapper to calloc() */
void *
xcalloc(size_t nmemb, size_t size)
{
  void *ptr;

  if ((ptr = calloc(nmemb, size)) == NULL)
    proto_server_log(NJT_LOG_DEBUG, "Unable to calloc memory - failed.");

  return (ptr);
}

void *
xrealloc(void *oldptr, size_t size)
{
  void *newptr;

  if ((newptr = realloc(oldptr, size)) == NULL)
    proto_server_log(NJT_LOG_DEBUG, "Unable to reallocate memory - failed");

  return (newptr);
}

static char *
strtoupper(char *str)
{
  char *p = str;
  if (str == NULL || *str == '\0')
    return str;

  while (*p != '\0')
  {
    *p = toupper((int)*p);
    p++;
  }

  return str;
}

static const char *
ws_get_method(const char *token)
{
  const char *lookfor = NULL;

  if ((lookfor = "GET", !memcmp(token, "GET ", 4)) ||
      (lookfor = "get", !memcmp(token, "get ", 4)))
    return lookfor;
  return NULL;
}

char *
base64_encode(const void *buf, size_t size)
{
  static const char base64[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  char *str = (char *)xmalloc((size + 3) * 4 / 3 + 1);

  char *p = str;
  const unsigned char *q = (const unsigned char *)buf;
  size_t i = 0;

  while (i < size)
  {
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
ws_set_header_key_value(TccWSHeaders *headers, char *key, char *value)
{
  if (strcasecmp("Host", key) == 0)
    headers->host = xstrdup(value);
  else if (strcasecmp("Origin", key) == 0)
    headers->origin = xstrdup(value);
  else if (strcasecmp("Upgrade", key) == 0)
    headers->upgrade = xstrdup(value);
  else if (strcasecmp("Connection", key) == 0)
    headers->connection = xstrdup(value);
  else if (strcasecmp("Sec-WebSocket-Protocol", key) == 0)
    headers->ws_protocol = xstrdup(value);
  else if (strcasecmp("Sec-WebSocket-Key", key) == 0)
    headers->ws_key = xstrdup(value);
  else if (strcasecmp("Sec-WebSocket-Version", key) == 0)
    headers->ws_sock_ver = xstrdup(value);
  else if (strcasecmp("User-Agent", key) == 0)
    headers->agent = xstrdup(value);
  else if (strcasecmp("Referer", key) == 0)
    headers->referer = xstrdup(value);
}

static char *
ws_parse_request(char *line, char **method, char **protocol)
{
  const char *meth;
  char *req = NULL, *request = NULL, *proto = NULL;
  ptrdiff_t rlen;

  if ((meth = ws_get_method(line)) == NULL)
  {
    return NULL;
  }
  else
  {
    req = line + strlen(meth);
    if ((proto = strstr(line, " HTTP/1.0")) == NULL &&
        (proto = strstr(line, " HTTP/1.1")) == NULL)
      return NULL;

    req++;
    if ((rlen = proto - req) <= 0)
      return NULL;

    request = xmalloc(rlen + 1);
    strncpy(request, req, rlen);
    request[rlen] = 0;

    (*method) = strtoupper(xstrdup(meth));
    (*protocol) = strtoupper(xstrdup(++proto));
  }

  return request;
}

static int
ws_set_header_fields(char *line, TccWSHeaders *headers)
{
  char *path = NULL, *method = NULL, *proto = NULL, *p, *value;

  if (line[0] == '\n' || line[0] == '\r')
    return 1;

  if ((strstr(line, "GET ")) || (strstr(line, "get ")))
  {
    if ((path = ws_parse_request(line, &method, &proto)) == NULL)
      return 1;
    headers->path = path;
    headers->method = method;
    headers->protocol = proto;

    return 0;
  }

  if ((p = strchr(line, ':')) == NULL)
    return 1;

  value = p + 1;
  while (p != line && isspace((unsigned char)*(p - 1)))
    p--;

  if (p == line)
    return 1;

  *p = '\0';
  if (strpbrk(line, " \t") != NULL)
  {
    *p = ' ';
    return 1;
  }
  while (isspace((unsigned char)*value))
    value++;

  ws_set_header_key_value(headers, line, value);

  return 0;
}

static int
parse_headers(TccWSHeaders *headers)
{
  char *tmp = NULL;
  const char *buffer = headers->buf;
  const char *line = buffer, *next = NULL;
  int len = 0;

  while (line)
  {
    if ((next = strstr(line, "\r\n")) != NULL)
      len = (next - line);
    else
      len = strlen(line);

    if (len <= 0)
    {
      proto_server_log(NJT_LOG_DEBUG, "1 tcc content parse_headers error!");
      return 1;
    }

    tmp = xmalloc(len + 1);
    memcpy(tmp, line, len);
    tmp[len] = '\0';

    if (ws_set_header_fields(tmp, headers) == 1)
    {
      free(tmp);
      proto_server_log(NJT_LOG_DEBUG, "2 tcc content parse_headers error!");
      return 1;
    }

    free(tmp);
    line = next ? (next + 2) : NULL;

    if (next && strcmp(next, "\r\n\r\n") == 0)
      break;
  }

  return 0;
}
static int
ws_verify_req_headers(TccWSHeaders *headers)
{
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
SHA1Init(SHA1_CTX *context)
{
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
  context->count[0] = context->count[1] = 0;
}
void SHA1Transform(uint32_t state[5], uint8_t buffer[64])
{
  uint32_t a, b, c, d, e;
  typedef union
  {
    uint8_t c[64];
    uint32_t l[16];
  } CHAR64LONG16;
  CHAR64LONG16 *block;
#ifdef SHA1HANDSOFF
  static uint8_t workspace[64];
  block = (CHAR64LONG16 *)(void *)workspace;
  memcpy(block, buffer, 64);
#else
  block = (CHAR64LONG16 *)(void *)buffer;
#endif
  /* Copy context->state[] to working vars */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  /* 4 rounds of 20 operations each. Loop unrolled. */
  R0(a, b, c, d, e, 0);
  R0(e, a, b, c, d, 1);
  R0(d, e, a, b, c, 2);
  R0(c, d, e, a, b, 3);
  R0(b, c, d, e, a, 4);
  R0(a, b, c, d, e, 5);
  R0(e, a, b, c, d, 6);
  R0(d, e, a, b, c, 7);
  R0(c, d, e, a, b, 8);
  R0(b, c, d, e, a, 9);
  R0(a, b, c, d, e, 10);
  R0(e, a, b, c, d, 11);
  R0(d, e, a, b, c, 12);
  R0(c, d, e, a, b, 13);
  R0(b, c, d, e, a, 14);
  R0(a, b, c, d, e, 15);
  R1(e, a, b, c, d, 16);
  R1(d, e, a, b, c, 17);
  R1(c, d, e, a, b, 18);
  R1(b, c, d, e, a, 19);
  R2(a, b, c, d, e, 20);
  R2(e, a, b, c, d, 21);
  R2(d, e, a, b, c, 22);
  R2(c, d, e, a, b, 23);
  R2(b, c, d, e, a, 24);
  R2(a, b, c, d, e, 25);
  R2(e, a, b, c, d, 26);
  R2(d, e, a, b, c, 27);
  R2(c, d, e, a, b, 28);
  R2(b, c, d, e, a, 29);
  R2(a, b, c, d, e, 30);
  R2(e, a, b, c, d, 31);
  R2(d, e, a, b, c, 32);
  R2(c, d, e, a, b, 33);
  R2(b, c, d, e, a, 34);
  R2(a, b, c, d, e, 35);
  R2(e, a, b, c, d, 36);
  R2(d, e, a, b, c, 37);
  R2(c, d, e, a, b, 38);
  R2(b, c, d, e, a, 39);
  R3(a, b, c, d, e, 40);
  R3(e, a, b, c, d, 41);
  R3(d, e, a, b, c, 42);
  R3(c, d, e, a, b, 43);
  R3(b, c, d, e, a, 44);
  R3(a, b, c, d, e, 45);
  R3(e, a, b, c, d, 46);
  R3(d, e, a, b, c, 47);
  R3(c, d, e, a, b, 48);
  R3(b, c, d, e, a, 49);
  R3(a, b, c, d, e, 50);
  R3(e, a, b, c, d, 51);
  R3(d, e, a, b, c, 52);
  R3(c, d, e, a, b, 53);
  R3(b, c, d, e, a, 54);
  R3(a, b, c, d, e, 55);
  R3(e, a, b, c, d, 56);
  R3(d, e, a, b, c, 57);
  R3(c, d, e, a, b, 58);
  R3(b, c, d, e, a, 59);
  R4(a, b, c, d, e, 60);
  R4(e, a, b, c, d, 61);
  R4(d, e, a, b, c, 62);
  R4(c, d, e, a, b, 63);
  R4(b, c, d, e, a, 64);
  R4(a, b, c, d, e, 65);
  R4(e, a, b, c, d, 66);
  R4(d, e, a, b, c, 67);
  R4(c, d, e, a, b, 68);
  R4(b, c, d, e, a, 69);
  R4(a, b, c, d, e, 70);
  R4(e, a, b, c, d, 71);
  R4(d, e, a, b, c, 72);
  R4(c, d, e, a, b, 73);
  R4(b, c, d, e, a, 74);
  R4(a, b, c, d, e, 75);
  R4(e, a, b, c, d, 76);
  R4(d, e, a, b, c, 77);
  R4(c, d, e, a, b, 78);
  R4(b, c, d, e, a, 79);
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  a = b = c = d = e = 0;
}

static void
SHA1Update(SHA1_CTX *context, uint8_t *data, unsigned int len)
{
  unsigned int i, j;

  j = (context->count[0] >> 3) & 63;
  if ((context->count[0] += len << 3) < (len << 3))
    context->count[1]++;
  context->count[1] += (len >> 29);
  if ((j + len) > 63)
  {
    memcpy(&context->buffer[j], data, (i = 64 - j));
    SHA1Transform(context->state, context->buffer);
    for (; i + 63 < len; i += 64)
    {
      SHA1Transform(context->state, &data[i]);
    }
    j = 0;
  }
  else
    i = 0;
  memcpy(&context->buffer[j], &data[i], len - i);
}

static void
SHA1Final(uint8_t digest[20], SHA1_CTX *context)
{
  uint32_t i, j;
  uint8_t finalcount[8];

  for (i = 0; i < 8; i++)
  {
    finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255); /* Endian independent */
  }
  SHA1Update(context, (uint8_t *)"\200", 1);
  while ((context->count[0] & 504) != 448)
  {
    SHA1Update(context, (uint8_t *)"\0", 1);
  }
  SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
  for (i = 0; i < 20; i++)
  {
    digest[i] = (uint8_t)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
  }
  /* Wipe variables */
  i = j = 0;
  memset(context->buffer, 0, 64);
  memset(context->state, 0, 20);
  memset(context->count, 0, 8);
  memset(&finalcount, 0, 8);
#ifdef SHA1HANDSOFF /* make SHA1Transform overwrite its own static vars */
  SHA1Transform(context->state, context->buffer);
#endif
}
static void
ws_sha1_digest(char *s, int len, unsigned char *digest)
{
  SHA1_CTX sha;

  SHA1Init(&sha);
  SHA1Update(&sha, (uint8_t *)s, len);
  SHA1Final(digest, &sha);
}

static void
ws_set_handshake_headers(TccWSHeaders *headers)
{

  size_t klen = strlen(headers->ws_key);
  size_t mlen = strlen(WS_MAGIC_STR);
  size_t len = klen + mlen;
  char *s = xmalloc(klen + mlen + 1);
  uint8_t digest[SHA_DIGEST_LENGTH];

  memset(digest, 0, sizeof *digest);

  memcpy(s, headers->ws_key, klen);
  memcpy(s + klen, WS_MAGIC_STR, mlen + 1);

  ws_sha1_digest(s, len, digest);

  headers->ws_accept = base64_encode((unsigned char *)digest, sizeof(digest));
  headers->ws_resp = xstrdup(WS_SWITCH_PROTO_STR);

  if (!headers->upgrade)
    headers->upgrade = xstrdup("websocket");
  if (!headers->connection)
    headers->connection = xstrdup("Upgrade");

  free(s);
}
static void
ws_append_str(char **dest, const char *src)
{
  size_t curlen = strlen(*dest);
  size_t srclen = strlen(src);
  size_t newlen = curlen + srclen;

  char *str = xrealloc(*dest, newlen + 1);
  memcpy(str + curlen, src, srclen + 1);
  *dest = str;
}

static int
ws_send_handshake_headers(tcc_stream_request_t *r, TccWSHeaders *headers)
{
  int bytes = 0;
  char *str = xstrdup("");

  ws_append_str(&str, headers->ws_resp);
  ws_append_str(&str, CRLF);
  ws_append_str(&str, "Upgrade: ");
  ws_append_str(&str, headers->upgrade);
  ws_append_str(&str, CRLF);
  ws_append_str(&str, "Connection: ");
  ws_append_str(&str, headers->connection);
  ws_append_str(&str, CRLF);
  ws_append_str(&str, "Sec-WebSocket-Accept: ");
  ws_append_str(&str, headers->ws_accept);
  ws_append_str(&str, CRLF CRLF);

  bytes = proto_server_send(r, str, strlen(str));
  free(str);
  return bytes;
}

/* Allocate memory for a websocket frame */
static WSFrame *
new_wsframe(void)
{
  WSFrame *frame = xcalloc(1, sizeof(WSFrame));
  memset(frame->buf, 0, sizeof(frame->buf));
  frame->reading = 1;

  return frame;
}

static int ws_get_data(WSClient *client, char *buffer, int size)
{
  int len;
  len = size;
  if (client->msg.len < size)
  {
    len = client->msg.len;
  }
  memcpy(buffer, client->msg.data, len);
  client->msg.data = client->msg.data + len;
  client->msg.len = client->msg.len - len;
  client->r->used_len = client->r->used_len + len;
  return len;
}
static int
read_socket(WSClient *client, char *buffer, int size)
{
  int bytes = 0;
  bytes = ws_get_data(client, buffer, size);
  return bytes;
}

/* Read a websocket frame's header.
 *
 * On success, the number of bytes read is returned. */
static int
ws_read_header(WSClient *client, WSFrame *frm, int pos, int need)
{
  char *buf = frm->buf;
  int bytes = 0;
  if (client->msg.len == 0)
  {
    return 0;
  }

  /* read the first 2 bytes for basic frame info */
  if ((bytes = read_socket(client, buf + pos, need)) < 1)
  {
    return bytes;
  }
  frm->buflen += bytes;
  frm->buf[frm->buflen] = '\0'; /* null-terminate */

  return bytes;
}
static int
ws_set_status(WSClient *client, WSStatus status, int bytes)
{
  client->status = status;
  return bytes;
}

static int
ws_set_front_header_fields(WSClient *client)
{
  WSFrame **frm = &client->frame;
  char *buf = (*frm)->buf;

  (*frm)->fin = WS_FRM_FIN(*(buf));
  (*frm)->masking = WS_FRM_MASK(*(buf + 1));
  (*frm)->opcode = WS_FRM_OPCODE(*(buf));
  (*frm)->res = WS_FRM_R1(*(buf)) || WS_FRM_R2(*(buf)) || WS_FRM_R3(*(buf));

  /* should be masked and can't be using RESVd  bits */
  if (!(*frm)->masking || (*frm)->res)
  {
    proto_server_log(NJT_LOG_DEBUG, "tcc ws_set_front_header_fields masking=%d,res=%d", (*frm)->masking, (*frm)->res);
    return ws_set_status(client, WS_ERR | WS_CLOSE, 1);
  }

  return 0;
}

/* Set the extended payload length into the given pointer. */
static void
ws_set_extended_header_size(const char *buf, int *extended)
{
  uint64_t payloadlen = 0;
  /* determine the payload length, else read more data */
  payloadlen = WS_FRM_PAYLOAD(*(buf + 1));
  switch (payloadlen)
  {
  case WS_PAYLOAD_EXT16:
    *extended = 2;
    break;
  case WS_PAYLOAD_EXT64:
    *extended = 8;
    break;
  }
}

/* Set the masking key into our frame structure. */
static void
ws_set_masking_key(WSFrame *frm, const char *buf)
{
  uint64_t payloadlen = 0;

  /* determine the payload length, else read more data */
  payloadlen = WS_FRM_PAYLOAD(*(buf + 1));
  switch (payloadlen)
  {
  case WS_PAYLOAD_EXT16:
    memcpy(&frm->mask, buf + 4, sizeof(frm->mask));
    break;
  case WS_PAYLOAD_EXT64:
    memcpy(&frm->mask, buf + 10, sizeof(frm->mask));
    break;
  default:
    memcpy(&frm->mask, buf + 2, sizeof(frm->mask));
  }
}

/* Set the extended payload length into our frame structure. */
static void
ws_set_payloadlen(WSFrame *frm, const char *buf)
{
  uint64_t payloadlen = 0, len64;
  uint16_t len16;

  /* determine the payload length, else read more data */
  payloadlen = WS_FRM_PAYLOAD(*(buf + 1));
  switch (payloadlen)
  {
  case WS_PAYLOAD_EXT16:
    memcpy(&len16, (buf + 2), sizeof(uint16_t));
    frm->payloadlen = ntohs(len16);
    break;
  case WS_PAYLOAD_EXT64:
    memcpy(&len64, (buf + 2), sizeof(uint64_t));
    frm->payloadlen = be64toh(len64);
    break;
  default:
    frm->payloadlen = payloadlen;
  }
}

static int
ws_realloc_frm_payload(WSFrame *frm, WSMessage *msg)
{
  char *tmp = NULL;
  uint64_t newlen = 0;

  newlen = msg->payloadsz + frm->payloadlen;
  tmp = realloc(msg->payload, newlen);
  if (tmp == NULL && newlen > 0)
  {
    free(msg->payload);
    msg->payload = NULL;
    return 1;
  }
  msg->payload = tmp;

  return 0;
}

static void
ws_unmask_payload(char *buf, int len, int offset, unsigned char mask[])
{
  int i, j = 0;

  /* unmask data */
  for (i = offset; i < len; ++i, ++j)
  {
    buf[i] ^= mask[j % 4];
  }
}

static int
ws_error(WSClient *client, unsigned short code, const char *err)
{
  unsigned int len;
  unsigned short code_be;
  char buf[128] = {0};

  len = 2;
  code_be = htobe16(code);
  memcpy(buf, &code_be, 2);
  if (err)
    len += snprintf(buf + 2, sizeof buf - 4, "%s", err);

  return ws_send_frame(client, WS_OPCODE_CLOSE, buf, len);
}
static int
ws_read_payload(WSClient *client, WSMessage *msg, int pos, int need)
{
  char *buf = msg->payload;
  int bytes = 0;

  /* read the first 2 bytes for basic frame info */
  if ((bytes = read_socket(client, buf + pos, need)) < 1)
  {
    if (client->status & WS_CLOSE)
      ws_error(client, WS_CLOSE_UNEXPECTED, "Unable to read payload");
    return bytes;
  }
  msg->buflen += bytes;
  msg->payloadsz += bytes;

  return bytes;
}

static void
ws_free_message(WSClient *client)
{
  if (client->message && client->message->payload)
    free(client->message->payload);
  if (client->message)
    free(client->message);
  client->message = NULL;
}

static uint32_t
verify_utf8(uint32_t *state, const char *str, int len)
{
  int i;
  uint32_t type;

  for (i = 0; i < len; ++i)
  {
    type = utf8d[(uint8_t)str[i]];
    *state = utf8d[256 + (*state) * 16 + type];

    if (*state == UTF8_INVAL)
      break;
  }

  return *state;
}

int ws_validate_string(const char *str, int len)
{
  uint32_t state = UTF8_VALID;

  if (verify_utf8(&state, str, len) == UTF8_INVAL)
  {
    return 1;
  }
  if (state != UTF8_VALID)
  {
    return 1;
  }

  return 0;
}

static int
ws_handle_err(WSClient *client, unsigned short code, WSStatus status, const char *m)
{
  client->status = status;
  return ws_error(client, code, m);
}

static void
ws_handle_text_bin(WSClient *client, WSServer *server)
{
  tcc_str_t content, out_data;
  WSFrame **frm = &client->frame;
  WSMessage **msg = &client->message;
  int offset = (*msg)->mask_offset;

  if ((*frm)->opcode == WS_OPCODE_CONTINUATION)
  {
    // proto_server_log(NJT_LOG_DEBUG,"2 tcc websocket CONTINUATION\n");
  }
  /* All data frames after the initial data frame must have opcode 0 */
  if ((*msg)->fragmented && (*frm)->opcode != WS_OPCODE_CONTINUATION)
  {
    client->status = WS_ERR | WS_CLOSE;
    return;
  }

  /* RFC states that there is a new masking key per frame, therefore,
   * time to unmask... */
  ws_unmask_payload((*msg)->payload, (*msg)->payloadsz, offset, (*frm)->mask);
  /* Done with the current frame's payload */
  (*msg)->buflen = 0;
  /* Reading a fragmented frame */
  (*msg)->fragmented = 1;

  content.data = (*msg)->payload;
  content.len = (*msg)->payloadsz;

  if (!(*frm)->fin)
  {
    proto_server_log(NJT_LOG_DEBUG, "tcc frm CONTINUATION ws_get_frm_payload = %V!", &content);
    return;
  } else {
    proto_server_log(NJT_LOG_DEBUG, "tcc frm ws_get_frm_payload = %V!", &content);
  }
  // proto_server_log(NJT_LOG_DEBUG, "2 tcc ws_get_frm_payload = %V!",&content);
  /* validate text data encoded as UTF-8 */
  if ((*msg)->opcode == WS_OPCODE_TEXT)
  {
    if (ws_validate_string((*msg)->payload, (*msg)->payloadsz) != 0)
    {
      ws_handle_err(client, WS_CLOSE_INVALID_UTF8, WS_ERR | WS_CLOSE, NULL);
      proto_server_log(NJT_LOG_DEBUG, "3 tcc ws_get_frm_payload = %V!", &content);
      return;
    }
  }

  if ((*msg)->opcode != WS_OPCODE_CONTINUATION)
  {
    // ws_write_fifo (server->pipeout, (*msg)->payload, (*msg)->payloadsz);
  }
  content.data = (*msg)->payload;
  content.len = (*msg)->payloadsz;
  // proto_server_log(NJT_LOG_DEBUG, "4 tcc ws_get_frm_payload = %V!",&content);
  ws_generate_frame(WS_OPCODE_TEXT, content.data, content.len, &out_data);
  if (out_data.len > 0)
  {
    proto_server_send_others(client->r, out_data.data, out_data.len);
    free(out_data.data);
  }

  //proto_server_log(NJT_LOG_DEBUG, "5 tcc ws_get_frm_payload = %V!", &content);
  ws_free_message(client);
}

static void
ws_handle_pong(WSClient *client)
{
  WSFrame **frm = &client->frame;

  if (!(*frm)->fin)
  {
    return;
  }
  ws_free_message(client);
}

static int
ws_respond(WSClient *client, const char *buffer, int len)
{
  int bytes = 0;
  // size_t length = len;
  proto_server_send(client->r, (char *)buffer, len);
  return bytes;
}

static int
ws_send_frame(WSClient *client, WSOpcode opcode, const char *p, int sz)
{
  unsigned char buf[32] = {0};
  char *frm = NULL;
  uint64_t payloadlen = 0, u64;
  int hsize = 2;

  if (sz < 126)
  {
    payloadlen = sz;
  }
  else if (sz < (1 << 16))
  {
    payloadlen = WS_PAYLOAD_EXT16;
    hsize += 2;
  }
  else
  {
    payloadlen = WS_PAYLOAD_EXT64;
    hsize += 8;
  }

  buf[0] = 0x80 | ((uint8_t)opcode);
  switch (payloadlen)
  {
  case WS_PAYLOAD_EXT16:
    buf[1] = WS_PAYLOAD_EXT16;
    buf[2] = (sz & 0xff00) >> 8;
    buf[3] = (sz & 0x00ff) >> 0;
    break;
  case WS_PAYLOAD_EXT64:
    buf[1] = WS_PAYLOAD_EXT64;
    u64 = htobe64(sz);
    memcpy(buf + 2, &u64, sizeof(uint64_t));
    break;
  default:
    buf[1] = (sz & 0xff);
  }
  frm = xcalloc(hsize + sz, sizeof(unsigned char));
  memcpy(frm, buf, hsize);
  if (p != NULL && sz > 0)
    memcpy(frm + hsize, p, sz);

  ws_respond(client, frm, hsize + sz);
  free(frm);

  return 0;
}

static int
ws_generate_frame(WSOpcode opcode, const char *p, int sz, tcc_str_t *out_message)
{
  unsigned char buf[32] = {0};
  char *frm = NULL;
  uint64_t payloadlen = 0, u64;
  int hsize = 2;

  if (sz < 126)
  {
    payloadlen = sz;
  }
  else if (sz < (1 << 16))
  {
    payloadlen = WS_PAYLOAD_EXT16;
    hsize += 2;
  }
  else
  {
    payloadlen = WS_PAYLOAD_EXT64;
    hsize += 8;
  }

  buf[0] = 0x80 | ((uint8_t)opcode);
  switch (payloadlen)
  {
  case WS_PAYLOAD_EXT16:
    buf[1] = WS_PAYLOAD_EXT16;
    buf[2] = (sz & 0xff00) >> 8;
    buf[3] = (sz & 0x00ff) >> 0;
    break;
  case WS_PAYLOAD_EXT64:
    buf[1] = WS_PAYLOAD_EXT64;
    u64 = htobe64(sz);
    memcpy(buf + 2, &u64, sizeof(uint64_t));
    break;
  default:
    buf[1] = (sz & 0xff);
  }
  frm = xcalloc(hsize + sz, sizeof(unsigned char));
  memcpy(frm, buf, hsize);
  if (p != NULL && sz > 0)
    memcpy(frm + hsize, p, sz);

  out_message->data = frm;
  out_message->len = hsize + sz;

  return 0;
}

static void
ws_handle_ping(WSClient *client)
{
  WSFrame **frm = &client->frame;
  tcc_str_t content;
  WSMessage **msg = &client->message;
  char *buf = NULL, *tmp = NULL;
  int pos = 0, len = (*frm)->payloadlen, newlen = 0;

  /* RFC states that Control frames themselves MUST NOT be
   * fragmented. */
  if (!(*frm)->fin)
  {
    ws_handle_err(client, WS_CLOSE_PROTO_ERR, WS_ERR | WS_CLOSE, NULL);
    return;
  }

  /* Control frames are only allowed to have payload up to and
   * including 125 octets */
  if ((*frm)->payloadlen > 125)
  {
    ws_handle_err(client, WS_CLOSE_PROTO_ERR, WS_ERR | WS_CLOSE, NULL);
    return;
  }

  /* No payload from ping */
  if (len == 0)
  {
    ws_send_frame(client, WS_OPCODE_PONG, NULL, 0);
    return;
  }

  /* Copy the ping payload */
  pos = (*msg)->payloadsz - len;
  buf = xcalloc(len, sizeof(char));
  memcpy(buf, (*msg)->payload + pos, len);

  /* Unmask it */
  ws_unmask_payload(buf, len, 0, (*frm)->mask);

  /* Resize the current payload (keep an eye on this realloc) */
  newlen = (*msg)->payloadsz - len;
  tmp = realloc((*msg)->payload, newlen);
  if (tmp == NULL && newlen > 0)
  {
    free((*msg)->payload);
    free(buf);

    (*msg)->payload = NULL;
    client->status = WS_ERR | WS_CLOSE;
    return;
  }

  (*msg)->payload = tmp;
  (*msg)->payloadsz -= len;

  content.data = buf;
  content.len = len;
  //proto_server_log(NJT_LOG_DEBUG, "tcc ping!");

  ws_send_frame(client, WS_OPCODE_PONG, buf, len);

  (*msg)->buflen = 0; /* done with the current frame's payload */
  /* Control frame injected in the middle of a fragmented message. */
  if (!(*msg)->fragmented)
  {
    ws_free_message(client);
  }
  free(buf);
}

static int
ws_handle_close(WSClient *client)
{
  client->status = WS_ERR | WS_CLOSE;
  return ws_send_frame(client, WS_OPCODE_CLOSE, NULL, 0);
}

static void
ws_manage_payload_opcode(WSClient *client, WSServer *server)
{
  WSFrame **frm = &client->frame;
  WSMessage **msg = &client->message;

  switch ((*frm)->opcode)
  {
  case WS_OPCODE_CONTINUATION:
    proto_server_log(NJT_LOG_DEBUG, "tcc websocket CONTINUATION\n");
    /* first frame can't be a continuation frame */
    if (!(*msg)->fragmented)
    {
      client->status = WS_ERR | WS_CLOSE;
      break;
    }
    ws_handle_text_bin(client, server);
    break;
  case WS_OPCODE_TEXT:
    proto_server_log(NJT_LOG_DEBUG, "tcc websocket TEXT\n");
    client->message->opcode = (*frm)->opcode;
    ws_handle_text_bin(client, server);
    break;
  case WS_OPCODE_BIN:
    proto_server_log(NJT_LOG_DEBUG, "tcc websocket BIN\n");
    client->message->opcode = (*frm)->opcode;
    ws_handle_text_bin(client, server);
    break;
  case WS_OPCODE_PONG:
    proto_server_log(NJT_LOG_DEBUG, "tcc websocket PONG\n");
    ws_handle_pong(client);
    break;
  case WS_OPCODE_PING:
    proto_server_log(NJT_LOG_DEBUG, "tcc websocket PING\n");
    ws_handle_ping(client);
    break;
  default:
    proto_server_log(NJT_LOG_DEBUG, "tcc websocket CLOSE\n");
    ws_handle_close(client);
  }
}

static void
ws_free_frame(WSClient *client)
{
  if (client->frame)
    free(client->frame);
  client->frame = NULL;
}

static WSMessage *
new_wsmessage(void)
{
  WSMessage *msg = xcalloc(1, sizeof(WSMessage));

  return msg;
}

static int
ws_get_frm_payload(WSClient *client, WSServer *server)
{
  WSFrame **frm = NULL;
  WSMessage **msg = NULL;
  int bytes = 0, readh = 0, need = 0;

  if (client->message == NULL)
    client->message = new_wsmessage();

  frm = &client->frame;
  msg = &client->message;

  /* message within the same frame */
  if ((*msg)->payload == NULL && (*frm)->payloadlen)
    (*msg)->payload = xcalloc((*frm)->payloadlen, sizeof(char));
  /* handle a new frame */
  else if ((*msg)->buflen == 0 && (*frm)->payloadlen)
  {
    if (ws_realloc_frm_payload((*frm), (*msg)) == 1)
      return ws_set_status(client, WS_ERR | WS_CLOSE, 0);
  }

  readh = (*msg)->buflen;            /* read from so far */
  need = (*frm)->payloadlen - readh; /* need to read */
  if (need > 0)
  {
    if ((bytes = ws_read_payload(client, (*msg), (*msg)->payloadsz, need)) < 0)
      return bytes;
    if (bytes != need)
      return ws_set_status(client, WS_READING, bytes);
  }

  (*msg)->mask_offset = (*msg)->payloadsz - (*msg)->buflen;

  ws_manage_payload_opcode(client, server);
  ws_free_frame(client);

  return bytes;
}

static int
ws_get_frm_header(WSClient *client)
{
  WSFrame **frm = NULL;
  int bytes = 0, readh = 0, need = 0, offset = 0, extended = 0;

  if (client->frame == NULL)
  {
    client->frame = new_wsframe();
    proto_server_log(NJT_LOG_DEBUG, "tcc new_wsframe!");
  }
  else
  {
    proto_server_log(NJT_LOG_DEBUG, "tcc client->frame->reading=%d!", client->frame->reading);
  }

  frm = &client->frame;

  /* Read the first 2 bytes for basic frame info */
  readh = (*frm)->buflen; /* read from header so far */
  need = 2 - readh;       /* need to read */
  if (need > 0)
  {
    if ((bytes = ws_read_header(client, (*frm), readh, need)) < 1)
    {
      // proto_server_log(NJT_LOG_DEBUG, "1 tcc read %d!",bytes);
      return bytes;
    }
    if (bytes != need)
    {
      // proto_server_log(NJT_LOG_DEBUG, "2 tcc read %d!",bytes);
      return ws_set_status(client, WS_READING, bytes);
    }
  }
  offset += 2;

  if (ws_set_front_header_fields(client) != 0)
  {
    // proto_server_log(NJT_LOG_DEBUG, "3 tcc read %d!",bytes);
    return bytes;
  }

  ws_set_extended_header_size((*frm)->buf, &extended);
  /* read the extended header */
  readh = (*frm)->buflen;             /* read from header so far */
  need = (extended + offset) - readh; /* read from header field so far */
  if (need > 0)
  {
    if ((bytes = ws_read_header(client, (*frm), readh, need)) < 1)
    {
      // proto_server_log(NJT_LOG_DEBUG, "4 tcc read %d!",bytes);
      return bytes;
    }
    if (bytes != need)
    {
      // proto_server_log(NJT_LOG_DEBUG, "5 tcc read %d!",bytes);
      return ws_set_status(client, WS_READING, bytes);
    }
  }
  offset += extended;

  /* read the masking key */
  readh = (*frm)->buflen; /* read from header so far */
  need = (4 + offset) - readh;
  if (need > 0)
  {
    if ((bytes = ws_read_header(client, (*frm), readh, need)) < 1)
    {
      // proto_server_log(NJT_LOG_DEBUG, "6 tcc read %d!",bytes);
      return bytes;
    }
    if (bytes != need)
    {
      // proto_server_log(NJT_LOG_DEBUG, "7 tcc read %d!",bytes);
      return ws_set_status(client, WS_READING, bytes);
    }
  }
  offset += 4;

  ws_set_payloadlen((*frm), (*frm)->buf);
  ws_set_masking_key((*frm), (*frm)->buf);

  if ((*frm)->payloadlen > max_frm_size)
  {
    // proto_server_log(NJT_LOG_DEBUG, "8 tcc read %d!",bytes);
    return ws_set_status(client, WS_ERR | WS_CLOSE, bytes);
  }

  (*frm)->buflen = 0;
  (*frm)->reading = 0;
  (*frm)->payload_offset = offset;
  // proto_server_log(NJT_LOG_DEBUG, "9 tcc read %d!",bytes);
  return ws_set_status(client, WS_OK, bytes);
}

static int
ws_get_message(WSClient *client, WSServer *server)
{
  int bytes = 0;
  if ((client->frame == NULL) || (client->frame->reading))
  {
    if ((bytes = ws_get_frm_header(client)) < 1 || client->frame->reading)
    {
      proto_server_log(NJT_LOG_DEBUG, "tcc ws_get_frm_header bytes=%d!", bytes);
      return bytes;
    }
  }
  proto_server_log(NJT_LOG_DEBUG, "tcc ws_get_frm_payload!");
  return ws_get_frm_payload(client, server);
  return 1;
}

//===============================================================

int proto_server_process_connetion(tcc_stream_request_t *r)
{
  char buffer[1024] = {0};
  char ip[64] = "127.0.0.1";
  int ret;
  void *p = cli_malloc(r, r->addr_text->len + 1);
  memset((void *)p, 0, r->addr_text->len + 1);
  memcpy(p, (void *)r->addr_text->data, r->addr_text->len);
  ret = memcmp((void *)r->addr_text->data, ip, strlen(ip));

  if (memcmp((void *)r->addr_text->data, ip, strlen(ip)) == 0)
  {
    proto_server_log(NJT_LOG_DEBUG, "1 tcc connetion ip=%s,NJT_STREAM_FORBIDDEN !", p);
    cli_free(r, p);
    return NJT_STREAM_FORBIDDEN;
  }
  proto_server_log(NJT_LOG_DEBUG, "1 tcc connetion ip=%s ok!", p);
  cli_free(r, p);
  return NJT_OK;
}
int proto_server_process_preread(tcc_stream_request_t *r, tcc_str_t *msg)
{
  void *p = cli_malloc(r, r->addr_text->len + 1);
  memset((void *)p, 0, r->addr_text->len + 1);
  memcpy(p, (void *)r->addr_text->data, r->addr_text->len);
  proto_server_log(NJT_LOG_DEBUG, "2 tcc preread ip=%s ok!", p);
  cli_free(r, p);
  return NJT_DECLINED;
}
int proto_server_process_log(tcc_stream_request_t *r)
{
  void *p = cli_malloc(r, r->addr_text->len + 1);
  memset((void *)p, 0, r->addr_text->len + 1);
  memcpy(p, (void *)r->addr_text->data, r->addr_text->len);
  proto_server_log(NJT_LOG_DEBUG, "4 tcc log ip=%s ok!", p);
  cli_free(r, p);
  return NJT_OK;
}
int proto_server_process_message(tcc_stream_request_t *r, tcc_str_t *msg)
{
  char buf[1024] = {0};
  char *data = NULL;
  WSctx *cli_ctx;
  int bytes;
  void *p = cli_malloc(r, r->addr_text->len + 1);
  memset((void *)p, 0, r->addr_text->len + 1);
  memcpy(p, (void *)r->addr_text->data, r->addr_text->len);

  proto_server_log(NJT_LOG_DEBUG, "3 tcc content tcc get=%V,len=%d", msg, msg->len);

  cli_ctx = tcc_get_client_ctx(r);
  if (cli_ctx == NULL)
  {
    cli_ctx = cli_malloc(r, sizeof(WSctx));
    memset(cli_ctx, 0, sizeof(WSctx));
    cli_ctx->client.r = r;
    tcc_set_client_ctx(r,cli_ctx);

  }

  if (cli_ctx->handshake == 0)
  {
    if (strstr(msg->data, "\r\n\r\n") == NULL)
    {
      cli_ctx->handshake = 1;
    }
  }
  if (cli_ctx->handshake == 0)
  {

    memset(&headers, 0, sizeof(headers));
    headers.buflen = msg->len;

    memcpy(headers.buf, msg->data, headers.buflen);
    headers.buf[headers.buflen] = '\0';

    data = headers.buf;

    if (strstr(data, "\r\n\r\n") == NULL)
    {
      proto_server_log(NJT_LOG_DEBUG, "tcc http error!");
      return NJT_AGAIN;
    }
    if (parse_headers(&headers) != 0)
    {
      proto_server_log(NJT_LOG_DEBUG, "tcc content parse_headers error!");
      return NJT_ERROR;
    }
    if (ws_verify_req_headers(&headers) != 0)
    {
      proto_server_log(NJT_LOG_DEBUG, "tcc content ws_verify_req_headers error!");
      return NJT_ERROR;
    }
    ws_set_handshake_headers(&headers);
    ws_send_handshake_headers(r, &headers);
    cli_ctx->handshake = WS_HANDSHAKE_OK;

    cli_ctx->client.r->used_len = msg->len;

    proto_server_log(NJT_LOG_DEBUG, "3 tcc content WS_HANDSHAKE_OK [%p,%p]!", cli_ctx, cli_ctx->client);
    return NJT_OK;
  }
  else
  {
    if (msg->len > 0)
    {
      cli_ctx->client.msg = *msg;
      bytes = ws_get_message(&cli_ctx->client, r->srv_ctx);
    }
  }

  proto_server_log(NJT_LOG_DEBUG, "tcc get ws data3 msg->len=%d,used_len=%d!", msg->len, cli_ctx->client.r->used_len);
  cli_free(r, p);
  if (r->used_len != msg->len)
  {
    return NJT_AGAIN;
  }
  return NJT_OK;
}
int proto_server_process_client_update(tcc_stream_request_t *r)
{
  char buf[1024] = {0};
  void *p = malloc(r->addr_text->len + 1);
  memset((void *)p, 0, r->addr_text->len + 1);
  memcpy(p, (void *)r->addr_text->data, r->addr_text->len);
  if (r->in_buf.last != r->in_buf.pos)
  {
    snprintf(buf, sizeof(buf), "ret:tcc client  update ip=%s,data %s\n", p, r->in_buf.pos);
  }
  else
  {
    snprintf(buf, sizeof(buf), "ret:tcc client update ip=%s\n", p);
  }
  // proto_server_send(r,buf,strlen(buf));
  // proto_server_send_broadcast(r->srv_ctx,buf,strlen(buf));

  proto_server_log(NJT_LOG_DEBUG, "%s", buf);
  free(p);
  return NJT_OK;
}

int proto_server_process_connection_close(tcc_stream_request_t *r)
{
  return NJT_OK;
}
int proto_server_update(tcc_stream_server_ctx *srv_ctx)
{
  char buf[1024] = "server data\n";
  // proto_server_send_broadcast(srv_ctx,buf,strlen(buf));
  proto_server_log(NJT_LOG_DEBUG, "tcc server update!");
  return NJT_OK;
}

int proto_server_init(tcc_stream_server_ctx *srv_ctx)
{
  srv_ctx->srv_data = srv_malloc(srv_ctx, sizeof(WSServer));
  return NJT_OK;
}

