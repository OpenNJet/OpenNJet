/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJT_RSYNC_COMMON_H
#define NJT_RSYNC_COMMON_H
#include <stdint.h>
#include <stdbool.h>
#include <njt_core.h>

typedef enum{
    NJT_HELPER_RSYNC_INOFIFY_TYPE_CONFIG = 0,
    NJT_HELPER_RSYNC_INOFIFY_TYPE_INTERNAL
}njt_helper_rsync_inotify_type;


typedef struct rsync_inotify_file_t{
    njt_str_t   watch_dir_prefix;
    njt_str_t   watch_dir_identifier;
    njt_str_t   watch_file;
    njt_int_t   watch_fd;
    njt_helper_rsync_inotify_type i_type;
}rsync_inotify_file;


njt_int_t njt_helper_rsync_watch_identifier_exist(njt_str_t identifier,
            rsync_inotify_file **watch_info);
njt_int_t njt_helper_rsync_del_watch_identifier_from_lvlhash(njt_str_t identifier);
njt_int_t njt_helper_rsync_add_watch_identifier_to_lvlhash(njt_str_t identifier,
        rsync_inotify_file *watch_info);



#endif /* NJT_RSYNC_COMMON_H */
