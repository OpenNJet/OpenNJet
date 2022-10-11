
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJT_DLOPEN_H_INCLUDED_
#define _NJT_DLOPEN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NJT_HAVE_DLOPEN  1


#define ngx_dlopen(path)           LoadLibrary((char *) path)
#define ngx_dlopen_n               "LoadLibrary()"

#define ngx_dlsym(handle, symbol)  (void *) GetProcAddress(handle, symbol)
#define ngx_dlsym_n                "GetProcAddress()"

#define ngx_dlclose(handle)        (FreeLibrary(handle) ? 0 : -1)
#define ngx_dlclose_n              "FreeLibrary()"


char *ngx_dlerror(void);


#endif /* _NJT_DLOPEN_H_INCLUDED_ */
