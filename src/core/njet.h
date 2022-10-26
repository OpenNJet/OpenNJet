
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#ifndef _NJT_H_INCLUDED_
#define _NJT_H_INCLUDED_


#define njet_version      1023001
#define NJT_VERSION      "1.23.1"
#define NJT_VER          "njet/" NJT_VERSION

#ifdef NJT_BUILD
#define NJT_VER_BUILD    NJT_VER " (" NJT_BUILD ")"
#else
#define NJT_VER_BUILD    NJT_VER
#endif

#define NJT_VAR          "NGINX"
#define NJT_OLDPID_EXT     ".oldbin"


#endif /* _NJT_H_INCLUDED_ */
