
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_DLOPEN_H_INCLUDED_
#define _NJT_DLOPEN_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define njt_dlopen(path)           dlopen((char *) path, RTLD_NOW | RTLD_GLOBAL)
#define njt_dlopen_n               "dlopen()"

#define njt_dlsym(handle, symbol)  dlsym(handle, symbol)
#define njt_dlsym_n                "dlsym()"

#define njt_dlclose(handle)        dlclose(handle)
#define njt_dlclose_n              "dlclose()"


#if (NJT_HAVE_DLOPEN)
char *njt_dlerror(void);
#endif


#endif /* _NJT_DLOPEN_H_INCLUDED_ */
