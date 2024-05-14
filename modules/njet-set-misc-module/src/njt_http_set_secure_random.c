#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <ndk.h>
#include "njt_http_set_secure_random.h"
#include <stdlib.h>


enum {
    MAX_RANDOM_STRING = 64,
    ALPHANUM = 1,
    LCALPHA  = 2
};


static njt_int_t
njt_http_set_misc_set_secure_random_common(int alphabet_type,
    njt_http_request_t *r, njt_str_t *res, njt_http_variable_value_t *v);


njt_int_t
njt_http_set_misc_set_secure_random_alphanum(njt_http_request_t *r,
    njt_str_t *res, njt_http_variable_value_t *v)
{
    return njt_http_set_misc_set_secure_random_common(ALPHANUM, r, res, v);
}


njt_int_t
njt_http_set_misc_set_secure_random_lcalpha(njt_http_request_t *r,
    njt_str_t *res, njt_http_variable_value_t *v)
{
    return njt_http_set_misc_set_secure_random_common(LCALPHA, r, res, v);
}


static njt_int_t
njt_http_set_misc_set_secure_random_common(int alphabet_type,
    njt_http_request_t *r, njt_str_t *res, njt_http_variable_value_t *v)
{
    static u_char  alphabet[] = "abcdefghijklmnopqrstuvwxyz"
                                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    u_char         entropy[MAX_RANDOM_STRING];
    u_char         output[MAX_RANDOM_STRING];
    njt_int_t      length, i;
    njt_fd_t       fd;
    ssize_t        n;

    length = njt_atoi(v->data, v->len);

    if (length == NJT_ERROR || length < 1 || length > MAX_RANDOM_STRING) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_random: bad \"length\" argument: %v", v);
        return NJT_ERROR;
    }

    fd = njt_open_file((u_char *) "/dev/urandom", NJT_FILE_RDONLY,
                       NJT_FILE_OPEN, 0);
    if (fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_secure_random: could not open /dev/urandom");
        return NJT_ERROR;
    }

    n = njt_read_fd(fd, entropy, length);
    if (n != length) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_secure_random: could not read all %i byte(s) from "
                      "/dev/urandom", length);
        njt_close_file(fd);
        return NJT_ERROR;
    }

    njt_close_file(fd);

    for (i = 0; i < length; i++) {
        if (alphabet_type == LCALPHA) {
            output[i] = entropy[i] % 26 + 'a';

        } else {
            output[i] = alphabet[ entropy[i] % (sizeof alphabet - 1) ];
        }
    }

    res->data = njt_palloc(r->pool, length);
    if (res->data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(res->data, output, length);

    res->len = length;

    /* set all required params */
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}
