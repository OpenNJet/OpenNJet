
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJET_H_INCLUDED_
#define _NJET_H_INCLUDED_


#define njet_version      1023001
#define NJET_VERSION      "1.23.1"
#define NJET_VER          "njet/" NJET_VERSION

#ifdef NGX_BUILD
#define NJET_VER_BUILD    NJET_VER " (" NGX_BUILD ")"
#else
#define NJET_VER_BUILD    NJET_VER
#endif

#define NJET_VAR          "NGINX"
#define NGX_OLDPID_EXT     ".oldbin"


#endif /* _NJET_H_INCLUDED_ */
