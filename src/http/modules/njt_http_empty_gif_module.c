
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static char *njt_http_empty_gif(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

static njt_command_t  njt_http_empty_gif_commands[] = {

    { njt_string("empty_gif"),
      NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS,
      njt_http_empty_gif,
      0,
      0,
      NULL },

      njt_null_command
};


/* the minimal single pixel transparent GIF, 43 bytes */

static u_char  njt_empty_gif[] = {

    'G', 'I', 'F', '8', '9', 'a',  /* header                                 */

                                   /* logical screen descriptor              */
    0x01, 0x00,                    /* logical screen width                   */
    0x01, 0x00,                    /* logical screen height                  */
    0x80,                          /* global 1-bit color table               */
    0x01,                          /* background color #1                    */
    0x00,                          /* no aspect ratio                        */

                                   /* global color table                     */
    0x00, 0x00, 0x00,              /* #0: black                              */
    0xff, 0xff, 0xff,              /* #1: white                              */

                                   /* graphic control extension              */
    0x21,                          /* extension introducer                   */
    0xf9,                          /* graphic control label                  */
    0x04,                          /* block size                             */
    0x01,                          /* transparent color is given,            */
                                   /*     no disposal specified,             */
                                   /*     user input is not expected         */
    0x00, 0x00,                    /* delay time                             */
    0x01,                          /* transparent color #1                   */
    0x00,                          /* block terminator                       */

                                   /* image descriptor                       */
    0x2c,                          /* image separator                        */
    0x00, 0x00,                    /* image left position                    */
    0x00, 0x00,                    /* image top position                     */
    0x01, 0x00,                    /* image width                            */
    0x01, 0x00,                    /* image height                           */
    0x00,                          /* no local color table, no interlaced    */

                                   /* table based image data                 */
    0x02,                          /* LZW minimum code size,                 */
                                   /*     must be at least 2-bit             */
    0x02,                          /* block size                             */
    0x4c, 0x01,                    /* compressed bytes 01_001_100, 0000000_1 */
                                   /* 100: clear code                        */
                                   /* 001: 1                                 */
                                   /* 101: end of information code           */
    0x00,                          /* block terminator                       */

    0x3B                           /* trailer                                */
};


static njt_http_module_t  njt_http_empty_gif_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


njt_module_t  njt_http_empty_gif_module = {
    NJT_MODULE_V1,
    &njt_http_empty_gif_module_ctx, /* module context */
    njt_http_empty_gif_commands,   /* module directives */
    NJT_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_str_t  njt_http_gif_type = njt_string("image/gif");


static njt_int_t
njt_http_empty_gif_handler(njt_http_request_t *r)
{
    njt_http_complex_value_t  cv;

    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD))) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    njt_memzero(&cv, sizeof(njt_http_complex_value_t));

    cv.value.len = sizeof(njt_empty_gif);
    cv.value.data = njt_empty_gif;
    r->headers_out.last_modified_time = 23349600;

    return njt_http_send_response(r, NJT_HTTP_OK, &njt_http_gif_type, &cv);
}


static char *
njt_http_empty_gif(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_empty_gif_handler;

    return NJT_CONF_OK;
}
