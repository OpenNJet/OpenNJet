/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_HTTP_UPSTREAM_API_H
#define NJT_HTTP_UPSTREAM_API_H

/*define the error code of the upstream api.
 * This is defined together with known http code such as 400 404 ..*/

#define NJT_HTTP_UPS_API_PATH_NOT_FOUND           700
#define NJT_HTTP_UPS_API_UPS_NOT_FOUND            701
#define NJT_HTTP_UPS_API_UNKNOWN_VERSION          702
#define NJT_HTTP_UPS_API_INVALID_SRVID            703
#define NJT_HTTP_UPS_API_SRV_NOT_FOUND            704
#define NJT_HTTP_UPS_API_INTERNAL_ERROR           705
#define NJT_HTTP_UPS_API_PERM_NOT_ALLOWED         706
#define NJT_HTTP_UPS_API_STATIC_UPS               707
#define NJT_HTTP_UPS_API_SRV_NOT_REMOVALBE        708
#define NJT_HTTP_UPS_API_METHOD_NOT_SUPPORTED     709
#define NJT_HTTP_UPS_API_TOO_LARGE_BODY           710
#define NJT_HTTP_UPS_API_INVALID_JSON_BODY        711
#define NJT_HTTP_UPS_API_MISS_SRV                 712
#define NJT_HTTP_UPS_API_MODIFY_SRV               713
#define NJT_HTTP_UPS_API_NOT_SUPPORTED_SRV        714
#define NJT_HTTP_UPS_API_ROUTE_INVALID_LEN        715
#define NJT_HTTP_UPS_API_INVALID_JSON_PARSE       716
#define NJT_HTTP_UPS_API_NO_RESOLVER              717
#define NJT_HTTP_UPS_API_WEIGHT_ERROR             718
#define NJT_HTTP_UPS_API_NOT_MODIFY_SRV_NAME      719
#define NJT_HTTP_UPS_API_INVALID_SRV_ARG          720
#define NJT_HTTP_UPS_API_RESET                    721
#define NJT_HTTP_UPS_API_NO_SRV_PORT              722
#define NJT_HTTP_UPS_API_INVALID_ERROR            723
#define NJT_HTTP_UPS_API_HAS_NO_BACKUP            724


#endif /* NJT_DYNAMIC_UPSTEAM_H */
