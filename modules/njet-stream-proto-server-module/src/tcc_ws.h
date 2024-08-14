#ifndef TCC_WS_H
#define TCC_WS_H

#include <netinet/in.h>
#include <njt_tcc.h>





#define WS_HANDSHAKE_OK          1 

#define UTF8_VALID 0
#define UTF8_INVAL 1

#define HDR_SIZE              3 * 4
#define WS_MAX_FRM_SZ         1048576   /* 1 MiB max frame size */
#define WS_THROTTLE_THLD      2097152   /* 2 MiB throttle threshold */
#define WS_MAX_HEAD_SZ        8192      /* a reasonable size for request headers */

#define WS_MAGIC_STR "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_PAYLOAD_EXT16      126
#define WS_PAYLOAD_EXT64      127
#define WS_PAYLOAD_FULL       125
#define WS_FRM_HEAD_SZ         16       /* frame header size */

#define WS_FRM_FIN(x)         (((x) >> 7) & 0x01)
#define WS_FRM_MASK(x)        (((x) >> 7) & 0x01)
#define WS_FRM_R1(x)          (((x) >> 6) & 0x01)
#define WS_FRM_R2(x)          (((x) >> 5) & 0x01)
#define WS_FRM_R3(x)          (((x) >> 4) & 0x01)
#define WS_FRM_OPCODE(x)      ((x) & 0x0F)
#define WS_FRM_PAYLOAD(x)     ((x) & 0x7F)

#define WS_CLOSE_NORMAL       1000
#define WS_CLOSE_GOING_AWAY   1001
#define WS_CLOSE_PROTO_ERR    1002
#define WS_CLOSE_INVALID_UTF8 1007
#define WS_CLOSE_TOO_LARGE    1009
#define WS_CLOSE_UNEXPECTED   1011

static const uint8_t utf8d[] = {
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 00..1f */
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 20..3f */
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 40..5f */
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 60..7f */
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, /* 80..9f */
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, /* a0..bf */
  8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, /* c0..df */
  0xa,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, /* e0..ef */
  0xb,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, /* f0..ff */
  0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, /* s0..s0 */
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, /* s1..s2 */
  1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, /* s3..s4 */
  1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, /* s5..s6 */
  1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* s7..s8 */
};

typedef enum WSOPCODE {
  WS_OPCODE_CONTINUATION = 0x00,
  WS_OPCODE_TEXT = 0x01,
  WS_OPCODE_BIN = 0x02,
  WS_OPCODE_END = 0x03,
  WS_OPCODE_CLOSE = 0x08,
  WS_OPCODE_PING = 0x09,
  WS_OPCODE_PONG = 0x0A,
} WSOpcode;

typedef enum WSSTATUS {
  WS_OK = 0,
  WS_ERR = (1 << 0),
  WS_CLOSE = (1 << 1),
  WS_READING = (1 << 2),
  WS_SENDING = (1 << 3),
  WS_THROTTLING = (1 << 4),
  WS_TLS_ACCEPTING = (1 << 5),
  WS_TLS_READING = (1 << 6),
  WS_TLS_WRITING = (1 << 7),
  WS_TLS_SHUTTING = (1 << 8),
} WSStatus;

/* WS HTTP Headers */
typedef struct TccWSHeaders_ {
  int reading;
  int buflen;
  char buf[WS_MAX_HEAD_SZ + 1];

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

/* A WebSocket Message */
typedef struct WSMessage_ {
  WSOpcode opcode;              /* frame opcode */
  int fragmented;               /* reading a fragmented frame */
  int mask_offset;              /* for fragmented frames */

  char *payload;                /* payload message */
  int payloadsz;                /* total payload size (whole message) */
  int buflen;                   /* recv'd buf length so far (for each frame) */
} WSMessage;

/* A WebSocket Message */
typedef struct WSFrame_ {
  /* frame format */
  WSOpcode opcode;              /* frame opcode */
  unsigned char fin;            /* frame fin flag */
  unsigned char mask[4];        /* mask key */
  uint8_t res;                  /* extensions */
  int payload_offset;           /* end of header/start of payload */
  int payloadlen;               /* payload length (for each frame) */

  /* status flags */
  int reading;                  /* still reading frame's header part? */
  int masking;                  /* are we masking the frame? */

  char buf[WS_FRM_HEAD_SZ + 1]; /* frame's header */
  int buflen;                   /* recv'd buf length so far (for each frame) */
} WSFrame;

/* A WebSocket Client */
typedef struct TCCWSClient_ {
  /* socket data */
  int listener;                 /* socket */
  char remote_ip[INET6_ADDRSTRLEN];     /* client IP */


  TccWSHeaders *headers;           /* HTTP headers */
  WSFrame *frame;               /* frame headers */
  WSMessage *message;           /* message */
  WSStatus status;              /* connection status */

  struct timeval start_proc;
  struct timeval end_proc;
  int used_len;
  tcc_str_t msg;
  tcc_stream_request_t *r;
#ifdef HAVE_LIBSSL
  SSL *ssl;
  WSStatus sslstatus;           /* ssl connection status */
#endif
} WSClient;

typedef struct  WSctx_ {
  unsigned       handshake:1;
  WSClient client;
  //tcc_stream_request_t *r;
  
} WSctx;


/* A WebSocket Instance */
typedef struct WSServer_ {
  /* Server Status */
  int closing;
} WSServer;



#endif
