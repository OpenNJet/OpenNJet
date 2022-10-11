
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_HAVE_DLOPEN)

char *
njt_dlerror(void)
{
    char  *err;

    err = (char *) dlerror();

    if (err == NULL) {
        return "";
    }

    return err;
}

#endif
