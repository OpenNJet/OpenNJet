#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <ndk.h>
#include "njt_http_set_quote_json.h"

njt_int_t
njt_http_set_misc_quote_json_str(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    size_t                   len;
    u_char                  *p;
    size_t                   escape;

    if (v->not_found || v->len == 0) {
        res->data = (u_char *) "null";
        res->len = sizeof("null") - 1;
        return NJT_OK;
    }

    escape = njt_http_set_misc_escape_json_str(NULL, v->data, v->len);

    len = sizeof("''") - 1
        + v->len
        + escape;

    p = njt_palloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    res->data = p;
    res->len = len;

    *p++ = '\"';

    if (escape == 0) {
        p = njt_copy(p, v->data, v->len);

    } else {
        p = (u_char *) njt_http_set_misc_escape_json_str(p, v->data, v->len);
    }

    *p++ = '\"';

    if (p != res->data + res->len) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_quote_sql_str: buffer error");
        return NJT_ERROR;
    }

    return NJT_OK;
}


uintptr_t
njt_http_set_misc_escape_json_str(u_char *dst, u_char *src, size_t size)
{
    njt_uint_t                   n;

    static u_char hex[] = "0123456789abcdef";

    if (dst == NULL) {
        /* find the number of characters to be escaped */

        n = 0;

        while (size) {
            /* UTF-8 char has high bit of 1 */
            if ((*src & 0x80) == 0) {
                switch (*src) {
                case '\r':
                case '\n':
                case '\\':
                case '"':
                case '\f':
                case '\b':
                case '\t':
                    n++;
                    break;
                default:
                    if (*src < 32) {
                        n += sizeof("\\u00xx") - 2;
                    }

                    break;
                }
            }

            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if ((*src & 0x80) == 0) {
            switch (*src) {
            case '\r':
                *dst++ = '\\';
                *dst++ = 'r';
                break;

            case '\n':
                *dst++ = '\\';
                *dst++ = 'n';
                break;

            case '\\':
                *dst++ = '\\';
                *dst++ = '\\';
                break;

            case '"':
                *dst++ = '\\';
                *dst++ = '"';
                break;

            case '\f':
                *dst++ = '\\';
                *dst++ = 'f';
                break;

            case '\b':
                *dst++ = '\\';
                *dst++ = 'b';
                break;

            case '\t':
                *dst++ = '\\';
                *dst++ = 't';
                break;

            default:
                if (*src < 32) { /* control chars */
                    *dst++ = '\\';
                    *dst++ = 'u';
                    *dst++ = '0';
                    *dst++ = '0';
                    *dst++ = hex[*src >> 4];
                    *dst++ = hex[*src & 0x0f];

                } else {
                    *dst++ = *src;
                }

                break;
            } /* switch */

            src++;

        } else {
            *dst++ = *src++;
        }

        size--;
    }

    return (uintptr_t) dst;
}


