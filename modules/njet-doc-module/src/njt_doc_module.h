
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef NJT_DOC_MODULE_H_
#define NJT_DOC_MODULE_H_
#include <njt_core.h>


#define CHUNK 512

typedef struct link_buf {
    unsigned char *buf;
    int out_len;
    struct link_buf* next;
} link_buf;


typedef struct
{
    njt_str_t untar_dir;
} njt_doc_conf_t;



#endif
