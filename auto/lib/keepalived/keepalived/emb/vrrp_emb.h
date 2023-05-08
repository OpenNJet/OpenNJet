/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef  vrrp_emb_INC
#define  vrrp_emb_INC
/* vrrp_emb_init: init vrrp ,read cfg, check etc.
*  0 means success
*/ 
int vrrp_emb_init(const char *cfg,const char* log);
/* vrrp_emb_run, run for ever, only returned on failure or on vrrp_emb_stop call */

void vrrp_emb_run(void);

void vrrp_emb_stop(void);
#endif   /* ----- #ifndef vrrp_emb_INC  ----- */
