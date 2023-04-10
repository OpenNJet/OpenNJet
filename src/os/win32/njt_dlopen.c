
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


char *
njt_dlerror(void)
{
    u_char         *p;
    static u_char   errstr[NJT_MAX_ERROR_STR];

    p = njt_strerror(njt_errno, errstr, NJT_MAX_ERROR_STR);
    *p = '\0';

    return (char *) errstr;
}
