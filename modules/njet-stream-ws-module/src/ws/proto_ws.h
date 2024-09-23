#ifndef TCC_WS_H
#define TCC_WS_H
#include "proto_ws_interface.h"

typedef struct websocket_parser_s websocket_parser_t;
typedef struct websocket_parser_settings websocket_parser_settings;



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
#define WS_OP_MASK 0xF
#define WS_FIN     WS_FINAL_FRAME

typedef int (*websocket_data_cb) (websocket_parser_t*, const char * at, size_t length);
typedef int (*websocket_cb) (websocket_parser_t*);


struct websocket_parser_s {
    uint32_t        state;
    websocket_flags flags;

    char            mask[4];
    uint8_t         mask_offset;

    size_t   length;
    size_t   require;
    size_t   offset;
    websocket_parser_settings *settings;
    void * data;
};


struct websocket_parser_settings {
    websocket_cb      on_frame_header;
    websocket_data_cb on_frame_body;
    websocket_cb      on_frame_end;
};

#define websocket_parser_get_opcode(p) (p->flags & WS_OP_MASK)
#define websocket_parser_has_mask(p) (p->flags & WS_HAS_MASK)
#define websocket_parser_has_final(p) (p->flags & WS_FIN)

#define TCC_PROTO_CTX_WS 3



void websocket_parser_init(websocket_parser_t *parser,websocket_parser_settings *settings);
void websocket_parser_settings_init(websocket_parser_settings *settings);

ssize_t websocket_parser_execute(websocket_parser_t * parser,    const char * data,    size_t len);


// Apply XOR mask (see https://tools.ietf.org/html/rfc6455#section-5.3) and store mask's offset
void websocket_parser_decode(char * dst, const char * src, size_t len, websocket_parser_t * parser);

// Apply XOR mask (see https://tools.ietf.org/html/rfc6455#section-5.3) and return mask's offset
uint8_t websocket_decode(char * dst, const char * src, size_t len, const char mask[4], uint8_t mask_offset);
#define websocket_encode(dst, src, len, mask, mask_offset) websocket_decode(dst, src, len, mask, mask_offset)

// Calculate frame size using flags and data length
size_t websocket_calc_frame_size(websocket_flags flags, size_t data_len);

// Create string representation of frame
size_t websocket_build_frame(char * frame, websocket_flags flags, const char mask[4], const char * data, size_t data_len);







#endif
