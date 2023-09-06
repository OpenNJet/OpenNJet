
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_H_INCLUDED_
#define _NJT_H_INCLUDED_


#define njet_version      1023001
#define NJT_VERSION      "1.2.0"
#define NJT_VER          "njet/" NJT_VERSION

#ifdef NJT_BUILD
#define NJT_VER_BUILD    NJT_VER " (" NJT_BUILD ")"
#else
#define NJT_VER_BUILD    NJT_VER
#endif

#define NJT_VAR          "NJET"
#define NJT_OLDPID_EXT     ".oldbin"


#endif /* _NJT_H_INCLUDED_ */
