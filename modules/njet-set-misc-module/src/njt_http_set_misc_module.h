#ifndef NJT_HTTP_SET_MISC_MODULE_H
#define NJT_HTTP_SET_MISC_MODULE_H


#include <njt_core.h>
#include <njt_config.h>
#include <njt_http.h>
#include <njet.h>


#ifndef NJT_HAVE_SHA1
#   if (nginx_version >= 1011002)
#       define NJT_HAVE_SHA1  1
#   endif
#endif


typedef struct {
    njt_flag_t          base32_padding;
    njt_str_t           base32_alphabet;
    u_char              basis32[256];
    njt_int_t           current;  /* for set_rotate */
} njt_http_set_misc_loc_conf_t;


extern njt_module_t  njt_http_set_misc_module;


#endif /* NJT_HTTP_SET_MISC_MODULE_H */

