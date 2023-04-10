
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


int njt_file_type(char *file, njt_file_info_t *sb)
{
    sb->dwFileAttributes = GetFileAttributes(file);

    if (sb->dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
        return -1;
    }

    return 0;
}

/*
int njt_stat(char *file, njt_stat_t *sb)
{
    *sb = GetFileAttributes(file);

    if (*sb == INVALID_FILE_ATTRIBUTES) {
        return -1;
    }

    return 0;
}
*/
