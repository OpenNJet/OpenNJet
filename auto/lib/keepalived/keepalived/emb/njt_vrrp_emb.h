/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef  NJT_VRRP_EMB_INC
#define  NJT_VRRP_EMB_INC
/* njt_vrrp_emb_init: init vrrp ,read cfg, check etc.
*  0 means success
*/ 
int njt_vrrp_emb_init(const char *cfg,const char* log);
/* njt_vrrp_emb_run, run for ever, only returned on failure or on njt_vrrp_emb_stop call */

void njt_vrrp_emb_run(void);

void njt_vrrp_emb_stop(void);
#endif   /* ----- #ifndef NJT_VRRP_EMB_INC  ----- */
