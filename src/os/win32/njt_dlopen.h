
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_DLOPEN_H_INCLUDED_
#define _NJT_DLOPEN_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_HAVE_DLOPEN  1


#define njt_dlopen(path)           LoadLibrary((char *) path)
#define njt_dlopen_n               "LoadLibrary()"

#define njt_dlsym(handle, symbol)  (void *) GetProcAddress(handle, symbol)
#define njt_dlsym_n                "GetProcAddress()"

#define njt_dlclose(handle)        (FreeLibrary(handle) ? 0 : -1)
#define njt_dlclose_n              "FreeLibrary()"


char *njt_dlerror(void);


#endif /* _NJT_DLOPEN_H_INCLUDED_ */
