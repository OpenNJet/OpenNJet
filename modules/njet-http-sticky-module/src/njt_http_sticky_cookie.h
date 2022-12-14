/*
 * Copyright (C) 2002-2021 Igor Sysoev
 * Copyright (C) 2011-2021 Nginx, Inc.
 * Copyright (C) 2022, by 通明智云（北京）科技有限公司
 * All rights reserved.
 */

#ifndef NJT_HTTP_STICKY_COOKIE_H_
#define NJT_HTTP_STICKY_COOKIE_H_

#include "njt_http_sticky_module.h"

#define MAX_EXPIRES_TIME -2
#define MAX_EXPIRES_STR "Thu, 31 Dec 2037 23:55:55 GMT"

char *njt_http_sticky_cookie_setup(njt_conf_t *cf, njt_http_sticky_conf_t *scf,
                                   njt_str_t *value);
njt_int_t njt_http_sticky_set_cookie(njt_http_request_t *r,
                                     njt_http_sticky_cookie_conf_t *cookie_conf,
                                     njt_str_t *md5);
njt_int_t njt_http_sticky_cookie_get_peer(njt_peer_connection_t *pc,
        njt_http_sticky_peer_data_t *sp);

#endif  // NJT_HTTP_STICKY_COOKIE_H_
